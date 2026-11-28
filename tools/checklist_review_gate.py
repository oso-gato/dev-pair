#!/usr/bin/python3
"""Check independently enforced main protection before a checklist proposal or merge."""
import re

import checklist_proposal as proposal
import job_protocol as p


def policy_identity(policy):
    return p.identity({'reviewer_ids': sorted(policy['reviewer_ids']), 'check': policy['check']})


def main_protection(trust, base, check):
    trust.main(base)
    rules = trust.api('branches/main/protection')
    required = rules['required_pull_request_reviews']
    status = rules['required_status_checks']
    p.require(rules['enforce_admins']['enabled'] is True and rules['allow_force_pushes']['enabled'] is False and
              rules['allow_deletions']['enabled'] is False and required['dismiss_stale_reviews'] is True and
              required['require_last_push_approval'] is True and
              type(required['required_approving_review_count']) is int and required['required_approving_review_count'] > 0
              and not any(required.get('bypass_pull_request_allowances', {}).values())
              and status['strict'] is True and {key: check[key] for key in ('context', 'app_id')} in status['checks'],
              'main requires enforced author-excluding review and strict trusted checks')
    trust.workflow(check['workflow'], base, check['sha256'])


def open_review(trust, pull, request, policy):
    number, head = pull['number'], request['candidate_sha']
    base, tree, check = request['base_sha'], request['tree_sha'], policy['check']
    protection = trust.api(f'pulls/{number}')
    proposal.match_pull(protection, request)
    p.require(protection['state'] == 'open' and protection['draft'] is False and protection['base']['sha'] == base,
              'proposal is no longer open on its authorized base')
    main_protection(trust, base, check)
    compared = trust.api(f'compare/{base}...{head}?per_page=100')
    files = compared['files']
    p.require(compared['status'] == 'ahead' and compared['ahead_by'] == 1 and compared['behind_by'] == 0 and
              1 <= len(files) <= len(proposal.CHECKLIST_FILES) and
              all(row['filename'] in proposal.CHECKLIST_FILES and row['status'] == 'modified' for row in files) and
              len({row['filename'] for row in files}) == len(files), 'independently observed changed paths exceed checklist scope')
    commit = trust.tree(head)
    p.require([parent['sha'] for parent in commit['parents']] == [base] and commit['tree']['sha'] == tree,
              'proposal head no longer identifies the tested candidate')
    reviews = trust.api(f'pulls/{number}/reviews?per_page=100', pages=True)
    latest = {}
    for review in reviews:
        actor = review['user']['id']
        if actor in policy['reviewer_ids'] and review['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
            latest[actor] = review
    if not any(row['commit_id'] == head and row['state'] == 'APPROVED' for row in latest.values()):
        return False
    checks = trust.api(f'commits/{head}/check-runs?filter=latest&per_page=100')['check_runs']
    passed = [row for row in checks if row['name'] == check['context'] and row['app']['id'] == check['app_id'] and
              row['head_sha'] == head and row['conclusion'] == 'success']
    if not passed:
        return False
    p.require(len(passed) == 1, 'ambiguous independently trusted exact-head check')
    run = passed[0]
    link = re.fullmatch(r'https://github\.com/' + proposal.REPOSITORY + r'/actions/runs/([1-9][0-9]*)/job/[1-9][0-9]*',
                        run['details_url'])
    p.require(link, 'required check lacks a trusted GitHub Actions run')
    workflow = trust.api('actions/runs/' + link[1])
    p.require(workflow['path'] == check['workflow'] and workflow['head_sha'] == head and
              workflow['event'] == 'pull_request' and workflow['conclusion'] == 'success' and
              workflow['repository']['full_name'] == proposal.REPOSITORY, 'required check did not come from pinned workflow')
    annotations = trust.api(f'check-runs/{run["id"]}/annotations?per_page=100', pages=True)
    evidence = [row for row in annotations if row.get('title') == 'dev-pair-release-tree']
    p.require(len(evidence) == 1 and evidence[0]['annotation_level'] == 'notice' and
              evidence[0]['path'] == check['workflow'], 'trusted check lacks unique tested tree evidence')
    proof = re.fullmatch(r'([0-9a-f]{40}):([0-9a-f]{40}):([0-9a-f]{40}):([0-9a-f]{40})', evidence[0]['message'])
    p.require(proof and proof[1] == head and proof[3] == tree,
              'trusted check did not test the authorized candidate on the reviewed base')
    tested = trust.tree(proof[2])
    p.require([parent['sha'] for parent in tested['parents']] == [base, head] and tested['tree']['sha'] == tree,
              'trusted check tested a different merge tree')
    trust.workflow(check['workflow'], proof[2], check['sha256'])
    trust.workflow(check['workflow'], proof[4], check['sha256'])
    return True
