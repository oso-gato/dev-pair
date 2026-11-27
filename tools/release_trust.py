#!/usr/bin/python3
"""Verify one exact postmerge release using the host's read-only GitHub identity."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from bootstrap import Blocked, Commands, checked_file, relay

REPOSITORY = 'oso-gato/dev-pair'
POLICY = Path('/etc/dev-pair/release-trust.json')
COMPONENTS = ('checklist', 'maintenance', 'development', 'devbox', 'host')
SHA = r'[0-9a-f]{40}'
DIGEST = r'[0-9a-f]{64}'
REGISTRY = r'ghcr\.io/oso-gato/[a-z0-9]+(?:[._/-][a-z0-9]+)*'
WORKFLOW = r'\.github/workflows/[a-z0-9-]+\.yml'
GITHUB = '/usr/bin/gh'


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def protect(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'release input requires a canonical absolute path')
    for entry in [path, *path.parents]:
        info = entry.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and
                (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 if entry == path else stat.S_ISDIR(info.st_mode)),
                'release input must be a unique root-owned file beneath protected directories')
    return path


def file_digest(path):
    path = protect(path)
    deadline = time.monotonic() + 300
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        require(0 < info.st_size <= 16 * 1024**3, 'release file exceeds supported intake size')
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            require(time.monotonic() < deadline, 'release file read exceeded its deadline')
            block = stream.read(min(1024**2, remaining))
            require(bool(block), 'release file shortened during verification')
            digest.update(block)
            remaining -= len(block)
        observed = path.stat()
        require(not stream.read(1) and (observed.st_dev, observed.st_ino, observed.st_size, observed.st_ctime_ns) ==
                (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns), 'release file changed during verification')
    return digest.hexdigest()


class ReleaseTrust:
    def __init__(self, run=None):
        self.run = run or Commands()

    def api(self, endpoint, *, pages=False):
        args = ['--paginate', '--slurp'] if pages else []
        raw = self.run(GITHUB, 'api', '--hostname', 'github.com', *args,
                       '-H', 'Accept: application/vnd.github+json', '-X', 'GET', 'repos/' + REPOSITORY + '/' + endpoint,
                       timeout=20)
        data = json.loads(raw, object_pairs_hook=relay.unique)
        if pages:
            require(type(data) is list and all(type(page) is list for page in data), 'GitHub review evidence shape invalid')
            return [value for page in data for value in page]
        return data

    def policy(self, component):
        value = json.loads(checked_file(protect(POLICY)).read_bytes(), object_pairs_hook=relay.unique)
        require(type(value) is dict and set(value) == {'version', 'reviewer_ids', 'check', 'components'}
                and type(value.get('version')) is int and value['version'] == 1,
                'unsupported independently provisioned release policy')
        reviewers, check = value['reviewer_ids'], value['check']
        require(type(reviewers) is list and 1 <= len(reviewers) <= 32
                and all(type(item) is int and item > 0 for item in reviewers) and len(set(reviewers)) == len(reviewers)
                and type(check) is dict and set(check) == {'context', 'app_id', 'workflow', 'sha256'}
                and type(check['context']) is str and re.fullmatch(r'[A-Za-z0-9 /_.()-]{1,100}', check['context'])
                and type(check['app_id']) is int and check['app_id'] > 0
                and type(check['workflow']) is str and re.fullmatch(WORKFLOW, check['workflow'])
                and type(check['sha256']) is str and re.fullmatch(DIGEST, check['sha256']),
                'independent review and trusted required check policy is invalid')
        components = value['components']
        require(type(components) is dict and set(components) <= set(COMPONENTS) and component in components,
                'component lacks protected publisher authorization')
        publisher = components[component]
        require(type(publisher) is dict and set(publisher) == {'workflow', 'registry', 'sha256'}
                and type(publisher['workflow']) is str and re.fullmatch(WORKFLOW, publisher['workflow'])
                and type(publisher['sha256']) is str and re.fullmatch(DIGEST, publisher['sha256'])
                and (publisher['registry'] is None or type(publisher['registry']) is str and
                     re.fullmatch(REGISTRY, publisher['registry'])), 'protected publisher identity is invalid')
        return value

    def main(self, source):
        branch = self.api('branches/main')
        require(branch['protected'] is True and branch['commit']['sha'] == source,
                'protected main no longer identifies the requested release revision')
        return branch

    def workflow(self, path, revision, expected_hash):
        value = self.api(f'contents/{path}?ref={revision}')
        require(value['path'] == path and value['type'] == 'file' and value['encoding'] == 'base64'
                and 0 < value['size'] <= 65536, 'independently pinned GitHub workflow is unavailable')
        data = base64.b64decode(''.join(value['content'].splitlines()), validate=True)
        require(len(data) == value['size'] and hashlib.sha256(data).hexdigest() == expected_hash,
                'workflow bytes differ from independently held release policy')

    def checklist_environment(self):
        env = self.api('environments/checklist-release')
        policy = self.api('environments/checklist-release/deployment-branch-policies?per_page=100')
        branches = [(item['name'], item['type']) for item in policy['branch_policies']]
        require(env['name'] == 'checklist-release' and env['deployment_branch_policy'] == {
                    'protected_branches': False, 'custom_branch_policies': True}
                and policy['total_count'] == 1 and branches == [('main', 'branch')],
                'checklist registry writer environment is not restricted to main')

    def review(self, source, policy):
        check = policy['check']
        self.main(source)
        rules = self.api('branches/main/protection')
        required = rules['required_pull_request_reviews']
        status = rules['required_status_checks']
        require(rules['enforce_admins']['enabled'] is True and rules['allow_force_pushes']['enabled'] is False
                and rules['allow_deletions']['enabled'] is False and required['dismiss_stale_reviews'] is True
                and required['require_last_push_approval'] is True
                and type(required['required_approving_review_count']) is int
                and required['required_approving_review_count'] > 0
                and not any(required.get('bypass_pull_request_allowances', {}).values())
                and status['strict'] is True and {key: check[key] for key in ('context', 'app_id')} in status['checks'],
                'main lacks the enforced independent review and check policy')
        pulls = self.api(f'commits/{source}/pulls?per_page=100', pages=True)
        links = [row for row in pulls if row['merge_commit_sha'] == source and row['base']['ref'] == 'main'
                 and row['base']['repo']['full_name'] == REPOSITORY and row['merged_at']]
        require(len(links) == 1 and type(links[0]['number']) is int and links[0]['number'] > 0,
                'release source is not one exact merged pull request into main')
        number = links[0]['number']
        pull = self.api(f'pulls/{number}')
        head = pull['head']['sha']
        require(pull['merged'] is True and pull['merge_commit_sha'] == source and re.fullmatch(SHA, head)
                and pull['base']['ref'] == 'main' and pull['base']['repo']['full_name'] == REPOSITORY,
                'merged pull request no longer binds its exact reviewed head')
        author = pull['user']['id']
        merge_actor = pull['merged_by']['id']
        reviewers = set(policy['reviewer_ids']) - {author, merge_actor}
        reviews = self.api(f'pulls/{number}/reviews?per_page=100', pages=True)
        latest = {}
        for review in reviews:
            user = review['user']['id']
            if user in reviewers and review['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
                latest[user] = review
        accepted = [review['id'] for review in latest.values()
                    if review['commit_id'] == head and review['state'] == 'APPROVED']
        require(bool(accepted), 'no eligible independent approval of the current head')
        self.workflow(check['workflow'], head, check['sha256'])
        checks = self.api(f'commits/{head}/check-runs?filter=latest&per_page=100')
        passed = [run for run in checks['check_runs']
                  if run['name'] == check['context'] and run['app']['id'] == check['app_id']
                  and run['head_sha'] == head and run['conclusion'] == 'success']
        require(len(passed) == 1, 'required trusted check did not pass on the exact reviewed head')
        details = re.fullmatch(r'https://github\.com/' + REPOSITORY + r'/actions/runs/([1-9][0-9]*)/job/[1-9][0-9]*',
                               passed[0]['details_url'])
        require(details, 'required check lacks a trusted GitHub Actions run')
        check_workflow = self.api('actions/runs/' + details[1])
        require(check_workflow['path'] == check['workflow'] and check_workflow['head_sha'] == head
                and check_workflow['event'] == 'pull_request' and check_workflow['conclusion'] == 'success'
                and check_workflow['repository']['full_name'] == REPOSITORY,
                'required check was not produced by the independently pinned workflow')
        return {'pull_request': number, 'review_head': head, 'reviews': sorted(accepted), 'check_run': passed[0]['id']}

    def verify(self, component, source, subject, run_id, *, artifact_sha256=None):
        require(component in COMPONENTS and type(source) is str and re.fullmatch(SHA, source)
                and type(run_id) is int and run_id > 0, 'exact source and positive publisher run ID required')
        policy = self.policy(component)
        publisher = policy['components'][component]
        if artifact_sha256 is None:
            registry = publisher['registry']
            require(registry and re.fullmatch(re.escape(registry) + '@sha256:' + DIGEST, subject),
                    'expected the approved registry repository at an exact manifest digest')
            artifact_sha256 = subject.rsplit(':', 1)[1]
            attestation_subject = 'oci://' + subject
        else:
            require(publisher['registry'] is None and re.fullmatch(DIGEST, artifact_sha256) and
                    file_digest(subject) == artifact_sha256, 'exact protected file digest required by the publisher policy')
            attestation_subject = subject
        review = self.review(source, policy)
        if component == 'checklist':
            self.checklist_environment()
        run = self.api(f'actions/runs/{run_id}')
        attempt = run['run_attempt']
        workflow = publisher['workflow']
        self.workflow(workflow, source, publisher['sha256'])
        require(run['id'] == run_id and type(attempt) is int and attempt > 0 and run['event'] == 'push'
                and run['status'] == 'completed' and run['conclusion'] == 'success'
                and run['head_branch'] == 'main' and run['head_sha'] == source
                and run['path'] == workflow and run['repository']['full_name'] == REPOSITORY
                and run['head_repository']['full_name'] == REPOSITORY,
                'publisher run is not the exact successful main push workflow')
        results = json.loads(self.run(GITHUB, 'attestation', 'verify', attestation_subject,
                                     '--hostname', 'github.com', '--repo', REPOSITORY, '--format', 'json',
                                     '--signer-workflow', REPOSITORY + '/' + workflow,
                                     '--source-ref', 'refs/heads/main', '--source-digest', source,
                                     '--signer-digest', source, '--deny-self-hosted-runners', timeout=60),
                             object_pairs_hook=relay.unique)
        invocation = f'https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}'
        for result in results:
            extensions = result['verificationResult']['signature']['certificate']['extensions']
            if extensions.get('runInvocationURI') == invocation and extensions.get('buildTrigger') == 'push':
                break
        else:
            raise Blocked('artifact attestation does not bind the exact trusted publication attempt')
        self.main(source)
        return {'version': 1, 'component': component, 'source_sha': source, 'subject': subject,
                'artifact_sha256': artifact_sha256, 'workflow': workflow, 'run_id': run_id, 'run_attempt': attempt, **review}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('verify',))
    parser.add_argument('--component', choices=COMPONENTS, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--subject', required=True, help='exact registry reference or protected local file')
    parser.add_argument('--sha256', help='independent local artifact SHA256')
    parser.add_argument('--run-id', type=int, required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'release verification uses the protected host transport identity')
        result = ReleaseTrust().verify(args.component, args.source_sha, args.subject, args.run_id,
                                       artifact_sha256=args.sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        print('release blocked: ' + (str(exc) if isinstance(exc, Blocked) else 'required GitHub or protected input evidence is unavailable'),
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
