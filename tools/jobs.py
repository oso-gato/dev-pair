#!/usr/bin/env python3
"""Trusted local controller CLI; see docs/durable-jobs.md for its boundary."""
import argparse
import json
import pathlib
import sys

from job_protocol import Ledger, canonical, loads, recipe_identity


def read_message(path):
    with open(path, 'rb') as stream:
        return loads(stream.read(65537))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, help='private controller-owned ledger directory (0700)')
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('job', 'checkpoint', 'submit'):
        child = commands.add_parser(command)
        child.add_argument('message', type=pathlib.Path)
    for command in ('status', 'consume'):
        child = commands.add_parser(command)
        child.add_argument('request_id')
    child = commands.add_parser('execute-local')
    child.add_argument('request_id')
    child.add_argument('--artifact', required=True, type=pathlib.Path)
    child = commands.add_parser('reconcile')
    child.add_argument('request_id')
    child.add_argument('--diagnostic', required=True)
    child.add_argument('--evidence', action='append', required=True)
    child = commands.add_parser('inspect')
    child.add_argument('job_id')
    child = commands.add_parser('request', help='produce and submit a fixed-recipe request for current checkpoint')
    child.add_argument('job_id')
    child.add_argument('request_id')
    child.add_argument('--expected-message', required=True)
    child.add_argument('--reason', required=True)
    child.add_argument('--boundary', choices=['local-protocol', 'fedora-host'], default='local-protocol')
    commands.add_parser('events')
    commands.add_parser('recipe')
    args = parser.parse_args(argv)
    if args.command == 'recipe':
        print(canonical(recipe_identity()))
        return 0
    ledger = Ledger(args.state)
    try:
        if args.command in ('job', 'checkpoint', 'submit'):
            message = read_message(args.message)
            result = {'job': ledger.create_job, 'checkpoint': ledger.checkpoint,
                      'submit': ledger.submit}[args.command](message)
        elif args.command == 'execute-local':
            result = ledger.execute(args.request_id, args.artifact)
        elif args.command == 'reconcile':
            result = ledger.reconcile(args.request_id, args.diagnostic, args.evidence)
        elif args.command == 'inspect':
            result = ledger.inspect(args.job_id)
        elif args.command == 'request':
            result = ledger.produce_request(args.job_id, args.request_id, args.expected_message, args.boundary, args.reason)
        elif args.command == 'events':
            result = ledger.events()
        else:
            result = getattr(ledger, args.command)(args.request_id)
        print(json.dumps(result, sort_keys=True, indent=2))
        # blocked/failed checks are data; only invocation/protocol errors exit 2.
        return 0
    finally:
        ledger.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as exc:
        print('Blocked: ' + str(exc), file=sys.stderr)
        sys.exit(2)
