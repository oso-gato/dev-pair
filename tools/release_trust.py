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
import subprocess
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
BASE_PREDICATE = 'https://github.com/oso-gato/dev-pair/checklist-base/v1'


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def base_policy(value):
    require(type(value) is dict and set(value) == {'image', 'repo', 'workflow', 'source', 'ref'}
            and all(type(item) is str for item in value.values())
            and re.fullmatch(r'[a-z0-9.-]+/[a-z0-9._/-]+@sha256:' + DIGEST, value['image'])
            and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value['repo'])
            and re.fullmatch(WORKFLOW, value['workflow']) and re.fullmatch(SHA, value['source'])
            and re.fullmatch(r'refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', value['ref']),
            'exact independently approved checklist base and signer required')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def protect(path, *, directory=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'release input requires a canonical absolute path')
    for entry in [path, *path.parents]:
        info = entry.lstat()
        leaf = entry == path and not directory
        require(info.st_uid == 0 and not info.st_mode & 0o022 and
                (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 if leaf else stat.S_ISDIR(info.st_mode)),
                'release input must have canonical root-owned custody')
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
        return self.validate_policy(value, component)

    @staticmethod
    def validate_policy(value, component):
        require(type(value) is dict and set(value) == {'version', 'reviewer_ids', 'check', 'components', 'writer_app_id'}
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
        required = {'workflow', 'registry', 'sha256'} | ({'base'} if component == 'checklist' else set())
        allowed = required | ({'agent_refresh'} if component in ('maintenance', 'development') else set())
        require(type(publisher) is dict and required <= set(publisher) <= allowed
                and type(publisher['workflow']) is str and re.fullmatch(WORKFLOW, publisher['workflow'])
                and type(publisher['sha256']) is str and re.fullmatch(DIGEST, publisher['sha256'])
                and (publisher['registry'] is None or type(publisher['registry']) is str and
                     re.fullmatch(REGISTRY, publisher['registry'])), 'protected publisher identity is invalid')
        if component == 'checklist':
            base_policy(publisher['base'])
        if 'agent_refresh' in publisher:
            refresh = publisher['agent_refresh']
            require(type(refresh) is dict and set(refresh) == {'workflow', 'sha256'} and publisher['registry'] is None
                    and type(refresh['workflow']) is str and re.fullmatch(WORKFLOW, refresh['workflow'])
                    and refresh['workflow'] != publisher['workflow'] and type(refresh['sha256']) is str
                    and re.fullmatch(DIGEST, refresh['sha256']), 'protected agent refresh publisher is invalid')
        return value

    def attestations(self, subject, repo, workflow, source, ref, *, predicate=None):
        predicate_args = ('--predicate-type', predicate) if predicate else ()
        result = json.loads(self.run(GITHUB, 'attestation', 'verify', subject, '--hostname', 'github.com',
                                     '--repo', repo, '--format', 'json', '--signer-workflow', repo + '/' + workflow,
                                     '--source-ref', ref, '--source-digest', source, '--signer-digest', source,
                                     '--deny-self-hosted-runners', '--limit', '20', *predicate_args, timeout=60),
                            object_pairs_hook=relay.unique)
        require(type(result) is list and 0 < len(result) <= 20, 'required verified provenance is unavailable')
        return [(entry['verificationResult']['signature']['certificate']['extensions'],
                 entry['verificationResult'].get('statement', {})) for entry in result]

    def verify_base(self, policy, invocation=None):
        policy = base_policy(policy)
        verified = self.attestations('oci://' + policy['image'], policy['repo'], policy['workflow'], policy['source'], policy['ref'])
        pattern = r'https://github\.com/' + re.escape(policy['repo']) + r'/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*'
        matching = sorted({extensions['runInvocationURI'] for extensions, _ in verified
                           if re.fullmatch(pattern, extensions.get('runInvocationURI', ''))})
        require(matching and (invocation is None or invocation in matching), 'approved upstream base signature or selected invocation is unavailable')
        return {'version': 1, 'policy': policy, 'invocation': invocation or matching[0]}

    @staticmethod
    def platform_subject(path, source, run_id, component, digest, event):
        try:
            from platform_release_protocol import COMPONENT, CONTROL_LIMIT, canonical as platform_bytes, json_bytes, portable_index
        except ModuleNotFoundError:
            raise Blocked('protected platform release index verifier is unavailable') from None
        path = protect(path)
        require(path.name == 'platform.json' and 0 < path.stat().st_size <= CONTROL_LIMIT,
                'expected the bounded portable platform.json attestation subject')
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == digest, 'portable signed index bytes changed')
        index = portable_index(json_bytes(raw), source, run_id)
        expected = 'dev-pair-platform-release' if event == 'push' else 'dev-pair-agent-release'
        name = 'host' if component == 'host' else COMPONENT[component]
        require(raw == platform_bytes(index) and index['kind'] == expected and name in index['components'],
                'portable release does not authorize the selected component for this event')
        return {'portable_kind': index['kind'], 'component_subject': index['components'][name]}

    def main(self, source):
        branch = self.api('branches/main')
        require(branch['protected'] is True and branch['commit']['sha'] == source,
                'protected main no longer identifies the requested release revision')
        return branch

    def workflow_hash(self, path, revision):
        value = self.api(f'contents/{path}?ref={revision}')
        require(value['path'] == path and value['type'] == 'file' and value['encoding'] == 'base64'
                and 0 < value['size'] <= 65536, 'independently pinned GitHub workflow is unavailable')
        data = base64.b64decode(''.join(value['content'].splitlines()), validate=True)
        require(len(data) == value['size'], 'independently pinned GitHub workflow size differs')
        return hashlib.sha256(data).hexdigest()

    def workflow(self, path, revision, expected_hash):
        require(self.workflow_hash(path, revision) == expected_hash,
                'workflow bytes differ from independently held release policy')

    def checklist_environment(self, writer_app_id):
        env = self.api('environments/checklist-release')
        policy = self.api('environments/checklist-release/deployment-branch-policies?per_page=100')
        branches = [(item['name'], item['type']) for item in policy['branch_policies']]
        require(env['name'] == 'checklist-release' and env['deployment_branch_policy'] == {
                    'protected_branches': False, 'custom_branch_policies': True}
                and policy['total_count'] == 1 and branches == [('main', 'branch')],
                'checklist registry writer environment is not restricted to main')
        rules = self.api('environments/checklist-release/deployment_protection_rules')
        installed = rules['custom_deployment_protection_rules']
        require(type(writer_app_id) is int and writer_app_id > 0 and rules['total_count'] == 1
                and len(installed) == 1 and installed[0]['enabled'] is True and installed[0]['app']['id'] == writer_app_id,
                'independently administered workflow-specific registry writer gate is unavailable')

    def tree(self, revision):
        info = self.api('git/commits/' + revision)
        require(info['sha'] == revision and re.fullmatch(SHA, info['tree']['sha']), 'GitHub commit lacks exact tree identity')
        return info

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
        annotations = self.api(f'check-runs/{passed[0]["id"]}/annotations?per_page=100', pages=True)
        evidence = [entry for entry in annotations if entry.get('title') == 'dev-pair-release-tree']
        require(len(evidence) == 1 and evidence[0]['annotation_level'] == 'notice'
                and evidence[0]['path'] == check['workflow'], 'trusted check lacks a unique tested tree and workflow annotation')
        match = re.fullmatch(f'({SHA}):({SHA}):({SHA}):({SHA})', evidence[0]['message'])
        require(match and match[1] == head, 'trusted check annotation does not bind the reviewed head')
        _, tested, tree, workflow_revision = match.groups()
        tested_commit = self.tree(tested)
        require([parent['sha'] for parent in tested_commit['parents']][1:] == [head]
                and tested_commit['tree']['sha'] == self.tree(head)['tree']['sha'] == self.tree(source)['tree']['sha'] == tree,
                'reviewed, tested merge and production source trees differ')
        self.workflow(check['workflow'], workflow_revision, check['sha256'])
        self.workflow(check['workflow'], tested, check['sha256'])
        return {'pull_request': number, 'review_head': head, 'reviews': sorted(accepted), 'check_run': passed[0]['id'],
                'tested_merge': tested, 'source_tree': tree, 'check_workflow_revision': workflow_revision}

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
            self.checklist_environment(policy['writer_app_id'])
        run = self.api(f'actions/runs/{run_id}')
        attempt = run['run_attempt']
        event = run['event']
        selected = publisher if event == 'push' else publisher.get('agent_refresh')
        require(selected and (event == 'push' or component in ('maintenance', 'development') and event in ('schedule', 'workflow_dispatch')),
                'publisher event lacks independent component authorization')
        platform = self.platform_subject(subject, source, run_id, component, artifact_sha256, event) if component != 'checklist' else {}
        workflow = selected['workflow']
        self.workflow(workflow, source, selected['sha256'])
        require(run['id'] == run_id and type(attempt) is int and attempt > 0
                and run['status'] == 'completed' and run['conclusion'] == 'success'
                and run['head_branch'] == 'main' and run['head_sha'] == source
                and run['path'] == workflow and run['repository']['full_name'] == REPOSITORY
                and run['head_repository']['full_name'] == REPOSITORY,
                'publisher run is not the exact authorized successful main workflow')
        results = self.attestations(attestation_subject, REPOSITORY, workflow, source, 'refs/heads/main')
        invocation = f'https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}'
        def same_run(extensions):
            return extensions.get('runInvocationURI') == invocation and extensions.get('buildTrigger') == event
        require(any(same_run(extensions) for extensions, _ in results), 'artifact attestation does not bind the exact trusted publication attempt')
        base = {}
        if component == 'checklist':
            results = self.attestations(attestation_subject, REPOSITORY, workflow, source, 'refs/heads/main', predicate=BASE_PREDICATE)
            proven = [statement['predicate'] for extensions, statement in results if same_run(extensions)]
            require(len(proven) == 1 and set(proven[0]) == {'proof', 'proof_sha256'}, 'publication lacks a unique signed base record')
            proof, digest = proven[0]['proof'], proven[0]['proof_sha256']
            require(type(proof) is dict and set(proof) == {'version', 'policy', 'invocation'}
                    and proof['policy'] == publisher['base'] and type(digest) is str
                    and hashlib.sha256((canonical(proof) + '\n').encode()).hexdigest() == digest,
                    'published base differs from independently approved base evidence')
            require(self.verify_base(publisher['base'], proof['invocation']) == proof,
                    'independent upstream base signature does not match the signed publication record')
            base['base'] = {'image': proof['policy']['image'], 'proof_sha256': digest, 'upstream_attempt': proof['invocation']}
        self.main(source)
        return {'version': 1, 'component': component, 'source_sha': source, 'subject': subject,
                'artifact_sha256': artifact_sha256, 'workflow': workflow, 'run_id': run_id, 'run_attempt': attempt,
                **review, **base, **platform}


def ci_base_proof():
    policy = json.loads(os.environ['CHECKLIST_BASE_POLICY'], object_pairs_hook=relay.unique)
    token = os.environ['GH_TOKEN']
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') == 'push' and token,
            'checklist base proof requires the protected publisher build job')

    def run(*args, timeout):
        env = {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C.UTF-8', 'HOME': str(Path.home()),
               'GH_TOKEN': token, 'GH_PROMPT_DISABLED': '1'}
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=env)
        require(result.returncode == 0 and len(result.stdout) <= 1024**2, 'approved base provenance verification failed')
        return result.stdout

    return canonical(ReleaseTrust(run).verify_base(policy))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    stages = parser.add_subparsers(dest='stage', required=True)
    stages.add_parser('checklist-base-proof')
    verify = stages.add_parser('verify')
    verify.add_argument('--component', choices=COMPONENTS, required=True)
    verify.add_argument('--source-sha', required=True)
    verify.add_argument('--subject', required=True, help='exact registry reference or protected local file')
    verify.add_argument('--sha256', help='independent local artifact SHA256')
    verify.add_argument('--run-id', type=int, required=True)
    args = parser.parse_args()
    try:
        if args.stage == 'checklist-base-proof':
            print(ci_base_proof())
            return 0
        require(os.geteuid() == 0, 'release verification uses the protected host transport identity')
        result = ReleaseTrust().verify(args.component, args.source_sha, args.subject, args.run_id,
                                       artifact_sha256=args.sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, subprocess.SubprocessError) as exc:
        print('release blocked: ' + (str(exc) if isinstance(exc, Blocked) else 'required GitHub or protected input evidence is unavailable'),
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
