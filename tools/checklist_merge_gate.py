#!/usr/bin/python3
"""Run the checked exact-head merge from the protected upstream workflow."""
import os
import re
import time
from urllib.parse import urlencode

from bootstrap import Blocked
import checklist_proposal as proposal
from checklist_review_gate import open_review, policy_identity
import job_protocol as p
from release_trust import ReleaseTrust

WORKFLOW = '.github/workflows/checklist-product-merge.yml'
PAGE_SIZE = 30
PAGES = 4


def load_policy(value):
    p.fields(value, 'version developer_id fork merge_actor_id reviewer_ids check expires_unix')
    p.number(value['version'], 1, 1)
    for key in ('developer_id', 'merge_actor_id'):
        p.number(value[key], 1, 2**63 - 1)
    p.number(value['expires_unix'], int(time.time()) + 1, int(time.time()) + 31 * 86400)
    reviewers = value['reviewer_ids']
    p.require(type(reviewers) is list and 1 <= len(reviewers) <= 32, 'bounded independent reviewer list required')
    for actor in reviewers:
        p.number(actor, 1, 2**63 - 1)
    p.require(len(set([*reviewers, value['developer_id'], value['merge_actor_id']])) == len(reviewers) + 2 and
              re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/dev-pair', value['fork']) and
              value['fork'].lower() != proposal.REPOSITORY.lower(), 'merge, proposal and review custody must be separate')
    check = value['check']
    p.fields(check, 'context app_id workflow sha256')
    p.text(check['context'], 100)
    p.number(check['app_id'], 1, 2**63 - 1)
    p.digest(check['sha256'])
    p.require(re.fullmatch(r'\.github/workflows/[a-z0-9-]+\.yml', check['workflow']), 'pinned required workflow needed')
    return value


class MergeHub(proposal.Hub):
    def merge(self, number, sha):
        p.number(number, 1, 2**31 - 1)
        p.digest(sha, 40)
        return proposal.json_data(proposal.capture(
            [proposal.GH, 'api', '--hostname', 'github.com', '-X', 'PUT',
             f'repos/{proposal.REPOSITORY}/pulls/{number}/merge', '--input', '-'],
            self.end, env={'GH_TOKEN': self.secret},
            data=p.canonical({'sha': sha, 'merge_method': 'merge'}).encode(), classify_http=True))


def proposals(hub, developer):
    p.number(developer, 1, 2**63 - 1)
    user = hub.get(f'user/{developer}')
    login = user['login']
    p.require(user['id'] == developer and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', login),
              'approved GitHub proposal actor is unavailable')
    seen = set()
    for page in range(1, PAGES + 1):
        query = urlencode({'q': f'repo:{proposal.REPOSITORY} is:pr is:open base:main author:{login}',
                           'sort': 'updated', 'order': 'desc', 'per_page': PAGE_SIZE, 'page': page})
        response = hub.get('search/issues?' + query)
        rows = response['items']
        p.require(response['incomplete_results'] is False and type(rows) is list and len(rows) <= PAGE_SIZE,
                  'approved proposal search is incomplete')
        for row in rows:
            number = row['number']
            p.number(number, 1, 2**31 - 1)
            if number not in seen:
                seen.add(number)
                yield number
        if len(rows) < PAGE_SIZE:
            break


def inspected_request(trust, number, policy):
    row = trust.api(f'pulls/{number}')
    body = row.get('body') or ''
    if row['user']['id'] != policy['developer_id'] or row['state'] != 'open' or not body.startswith(proposal.MARKER):
        return None
    req = proposal.request_shape(p.loads(body.removeprefix(proposal.MARKER).encode()))
    p.require(req['developer_id'] == policy['developer_id'] and req['fork'] == policy['fork'] and
              req['review_policy_sha256'] == policy_identity(policy), 'proposal is outside approved developer scope')
    proposal.match_pull(row, req)
    if trust.api('branches/main')['commit']['sha'] != req['base_sha'] or not open_review(trust, row, req, policy):
        return None
    row = trust.api(f'pulls/{number}')
    proposal.match_pull(row, req)
    p.require(row['state'] == 'open' and row['draft'] is False and row['base']['sha'] == req['base_sha'],
              'proposal changed immediately before protected merge')
    trust.main(req['base_sha'])
    return req


def act(hub, trust, policy):
    proposal.permissions(hub, proposal.REPOSITORY, policy['merge_actor_id'], push=True)
    holds = []
    for number in proposals(hub, policy['developer_id']):
        try:
            req = inspected_request(trust, number, policy)
        except proposal.AuthorityDenied:
            raise
        except (Blocked, ValueError, KeyError, TypeError, AttributeError, IndexError):
            holds.append({'pull_request': number, 'reason': 'proposal-shape-or-proof-rejected'})
            continue
        if req is None:
            continue
        # The service checks this exact head and applies protected branch rules to the merge.
        reply = hub.merge(number, req['candidate_sha'])
        p.require(reply['merged'] is True, 'GitHub declined the protected current-head merge')
        p.digest(reply['sha'], 40)
        observed = trust.api(f'pulls/{number}')
        proposal.match_pull(observed, req)
        p.require(observed['merged'] is True and observed['merge_commit_sha'] == reply['sha'] and
                  observed['merged_by']['id'] == policy['merge_actor_id'], 'exact merged outcome has yet to be observed')
        result = {'pull_request': number, 'merge_commit_sha': reply['sha']}
        break
    else:
        result = {'phase': 'awaiting-independent-review-or-current-check'}
    if holds:
        result['holds'] = holds
    return result


def main():
    repo = proposal.REPOSITORY
    p.require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == repo and
              os.environ.get('GITHUB_REF') == 'refs/heads/main' and
              os.environ.get('GITHUB_WORKFLOW_REF') == repo + '/' + WORKFLOW + '@refs/heads/main' and
              os.environ.get('GITHUB_EVENT_NAME') in ('schedule', 'workflow_dispatch'),
              'protected upstream checklist merge workflow required')
    policy = load_policy(p.loads(os.environ['PRODUCT_MERGE_POLICY'].encode()))
    hub = MergeHub(proposal.token(os.environ['CHECKLIST_MERGE_TOKEN'].encode()), time.monotonic() + 150)
    print(p.canonical(act(hub, ReleaseTrust(hub.gh), policy)))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit('Protected checklist merge withheld (' + type(exc).__name__ + ').') from None
