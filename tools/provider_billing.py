#!/usr/bin/python3 -IB
"""Exchange independently reviewed billing terms for one scoped OpenAI API key."""

import argparse
import base64
import binascii
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_protocol as p
from ledger_recovery import sync_directory, write_private

CREDENTIALS = Path('/etc/dev-pair/provider-credentials')
EVIDENCE = Path('/etc/dev-pair/provider-evidence')
SIGNERS = Path('/etc/dev-pair/trust/allowed_signers')
MODEL = 'gpt-6.2-sol'
EFFORT = 'high'
PROFILE = 'openai-api-key'
ALLOWANCE_KIND = 'verified-openai-project-context'
PRINCIPAL = 'provider-billing'
NAMESPACE = 'dev-pair-provider-billing'
CONTRACT = 'openai-responses-text-local-tools-default-tier-v1'
SOURCE_KINDS = ('context', 'tariff', 'response_models')
TERMS_LIFETIME = 30 * 86400
REVIEW_LIMIT = 16384
EVIDENCE_LIMIT = 262144
BUNDLE_LIMIT = 2 + 4 * len(SOURCE_KINDS) * EVIDENCE_LIMIT // 3 + 2 * REVIEW_LIMIT
MAX_REVIEWS = 64
SIGNATURE_LIMIT = 8192
SECRET_LIMIT = 513
SSH_KEYGEN = '/usr/bin/ssh-keygen'
ACTIVE = 'active.sha256'
PRICING = ('max_context_tokens', 'input_microusd_per_million', 'output_microusd_per_million', 'observed_models')


def canonical(value):
    return p.canonical(value).encode()


def protected(path, *, directory=False, private=False):
    p.require(path.is_absolute() and path.resolve(strict=True) == path, 'Billing input path is unsafe.')
    for member in (path, *path.parents):
        node = member.lstat()
        folder = member != path or directory
        p.require(node.st_uid == 0 and node.st_gid == 0 and not node.st_mode & 0o022 and
                  (stat.S_ISDIR(node.st_mode) if folder else stat.S_ISREG(node.st_mode) and node.st_nlink == 1),
                  'Billing input is outside protected root custody.')
    if private:
        p.require(stat.S_IMODE(path.lstat().st_mode) == (0o700 if directory else 0o600),
                  'Billing input needs private root custody.')
    return path


def bounded_file(path, limit, *, owner=None, mode=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        node = os.fstat(stream.fileno())
        p.require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and 0 < node.st_size <= limit and
                  (owner is None or (node.st_uid, node.st_gid) == (owner, owner)) and
                  (mode is None or stat.S_IMODE(node.st_mode) == mode), 'Billing input is unsafe or outside its byte bound.')
        raw = stream.read(limit + 1)
    p.require(len(raw) == node.st_size, 'Billing input changed while reading.')
    return raw


def credential(raw):
    try:
        value = raw.decode('ascii').removesuffix('\n')
    except UnicodeError as exc:
        raise ValueError('A scoped OpenAI project or service-account API key is required.') from exc
    p.require(re.fullmatch(r'sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,500}', value),
              'A scoped OpenAI project or service-account API key is required.')
    return value


def credential_from(path):
    return credential(bounded_file(protected(path, private=True), SECRET_LIMIT, owner=0, mode=0o600))


def fingerprint(secret):
    return hashlib.sha256(secret.encode('ascii')).hexdigest()


def request_record(reference, secret):
    p.token(reference)
    return {'schema': 1, 'credential_ref': reference, 'credential_sha256': fingerprint(secret),
            'profile': PROFILE, 'contract': CONTRACT, 'model': MODEL, 'effort': EFFORT}


def validate_request(row):
    p.fields(row, 'schema credential_ref credential_sha256 profile contract model effort')
    p.number(row['schema'], 1, 1)
    p.token(row['credential_ref'])
    p.digest(row['credential_sha256'])
    p.require((row['profile'], row['contract'], row['model'], row['effort']) == (PROFILE, CONTRACT, MODEL, EFFORT),
              'Billing review targets a different provider contract.')
    return row


def check_attachment(raw):
    p.require(not re.search(rb'sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,500}', raw),
              'Provider evidence attachments must exclude API keys.')


def organization(value):
    p.require(type(value) is str and re.fullmatch(r'org-[A-Za-z0-9_-]{6,96}', value),
              'Supply the exact OpenAI organization ID.')
    return value


def project(value):
    p.require(type(value) is str and re.fullmatch(r'proj_[A-Za-z0-9_-]{6,96}', value),
              'Supply the exact OpenAI project ID.')
    return value


def source_id(value):
    p.require(type(value) is str and len(value) <= 512 and all(32 < ord(char) < 127 for char in value),
              'Supply an official OpenAI URL or a provider correspondence/contract reference.')
    if re.fullmatch(r'record:[A-Za-z0-9][A-Za-z0-9._/-]{5,127}', value):
        return value
    url = urlsplit(value)
    p.require(url.scheme == 'https' and url.netloc in ('openai.com', 'platform.openai.com', 'developers.openai.com',
                                                     'help.openai.com') and url.path.startswith('/') and not url.query,
              'Supply an official OpenAI URL without query parameters or a provider record reference.')
    return value


def validate_review(review, now):
    p.fields(review, 'request organization project issued_unix expires_unix max_context_tokens '
             'input_microusd_per_million output_microusd_per_million observed_models sources')
    validate_request(review['request'])
    organization(review['organization'])
    project(review['project'])
    p.number(review['issued_unix'], 1, int(now))
    p.number(review['expires_unix'], int(now) + 1, review['issued_unix'] + TERMS_LIFETIME)
    p.number(review['max_context_tokens'], 1024, 2000000)
    for key in PRICING[1:3]:
        p.number(review[key], 1, 10**9)
    models = review['observed_models']
    p.require(type(models) is list and 0 < len(models) <= 8 and
              all(type(model) is str and re.fullmatch(r'gpt-[a-z0-9][a-z0-9.-]{1,95}', model) for model in models) and
              models == sorted(set(models)), 'Provider terms require exact reviewed response model names.')
    p.fields(review['sources'], ' '.join(SOURCE_KINDS))
    for row in review['sources'].values():
        p.fields(row, 'source sha256 bytes')
        source_id(row['source'])
        p.digest(row['sha256'])
        p.number(row['bytes'], 1, EVIDENCE_LIMIT)
    return review


def from_usd(value):
    p.require(re.fullmatch(r'(?:0|[1-9][0-9]{0,3})(?:\.[0-9]{1,6})?', value),
              'Enter an exact USD-per-million price with up to six decimals.')
    whole, _, fraction = value.partition('.')
    return int(whole) * 1000000 + int(fraction.ljust(6, '0'))


def openssh(*args, data):
    signing = args[0] == 'sign'
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    if signing and 'SSH_AUTH_SOCK' in os.environ:
        environment['SSH_AUTH_SOCK'] = os.environ['SSH_AUTH_SOCK']
    outcome = subprocess.run([SSH_KEYGEN, '-Y', *args], input=data, capture_output=True,
                             timeout=60 if signing else 10, env=environment)
    p.require(outcome.returncode == 0, 'The independently pinned OpenSSH billing signature could not be processed.')
    return outcome.stdout


def verify_signature(review, signature):
    p.require(type(signature) is str and 0 < len(signature) <= SIGNATURE_LIMIT and signature.isascii() and
              signature.startswith('-----BEGIN SSH SIGNATURE-----\n'), 'Billing review signature is invalid.')
    try:
        signers = protected(SIGNERS)
        with tempfile.TemporaryDirectory(prefix='provider-billing-') as directory:
            path = Path(directory) / 'review.sig'
            path.write_text(signature, encoding='ascii')
            openssh('verify', '-f', str(signers), '-I', PRINCIPAL, '-n', NAMESPACE, '-s', str(path),
                    data=canonical(review))
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('The pinned provider billing reviewer or signature verifier is unavailable.') from exc


def normalized(review, signature):
    pricing = {key: review[key] for key in PRICING}
    binding = {'billing_schema': 1, 'model': MODEL, 'review_sha256': review_digest(review)}
    return {'context': canonical(dict(binding, review=review, signature=signature,
                                       max_context_tokens=pricing['max_context_tokens'])),
            'tariff': canonical(dict(binding, **{key: pricing[key] for key in PRICING[1:]}))}


def validate_proofs(proofs, reference, *, now=None):
    context = p.loads(proofs['context'])
    p.fields(context, 'billing_schema model review_sha256 max_context_tokens review signature')
    review = validate_review(context['review'], time.time() if now is None else now)
    p.require(review['request']['credential_ref'] == reference and proofs == normalized(review, context['signature']),
              'The normalized billing record differs from the reviewed credential or provider terms.')
    verify_signature(review, context['signature'])
    return {key: review[key] for key in PRICING}, review


def reference_directory(reference):
    p.token(reference)
    return protected(EVIDENCE / reference, directory=True, private=True)


def current_digest(root):
    raw = bounded_file(protected(root / ACTIVE, private=True), 65, owner=0, mode=0o600)
    p.require(re.fullmatch(rb'[0-9a-f]{64}\n', raw), 'The active billing review pointer is invalid.')
    return raw[:-1].decode('ascii')


def review_digest(review):
    return p.sha256(canonical(review))


def proofs_at(root):
    protected(root, directory=True, private=True)
    return {kind: bounded_file(protected(root / (MODEL + '.' + kind), private=True), REVIEW_LIMIT,
                               owner=0, mode=0o600) for kind in ('context', 'tariff')}


def assert_current(review):
    reference = review['request']['credential_ref']
    p.require(review['expires_unix'] > time.time() and current_digest(reference_directory(reference)) ==
              review_digest(review), 'The signed billing review expired or was superseded.')


def authority(reference):
    root = reference_directory(reference)
    active = current_digest(root)
    secret = credential_from(CREDENTIALS / reference)
    review, proofs = authorize_bundle(retained_bundle(root / active), reference, secret)
    p.require(review_digest(review) == active and proofs_at(root / active) == proofs,
              'The active billing evidence no longer matches independent review.')
    return {key: review[key] for key in PRICING}, proofs, review


def retained_bundle(directory):
    return bounded_file(protected(directory / 'review.bundle', private=True), BUNDLE_LIMIT, owner=0, mode=0o600)


def authorize_bundle(raw, reference, secret):
    def reject_pairs(pairs):
        value = dict(pairs)
        p.require(len(value) == len(pairs), 'Duplicate fields in billing review bundle.')
        return value

    p.require(0 < len(raw) <= BUNDLE_LIMIT, 'Billing review bundle is missing or exceeds its bound.')
    try:
        bundle = json.loads(raw, object_pairs_hook=reject_pairs)
    except RecursionError as exc:
        raise ValueError('Billing review bundle exceeds its nesting bound.') from exc
    p.fields(bundle, 'review signature evidence')
    review = validate_review(bundle['review'], time.time())
    p.require(review['request'] == request_record(reference, secret), 'The review belongs to another credential.')
    verify_signature(review, bundle['signature'])
    p.fields(bundle['evidence'], ' '.join(SOURCE_KINDS))
    for key, body in bundle['evidence'].items():
        recorded = review['sources'][key]
        p.require(type(body) is str and len(body) == 4 * ((recorded['bytes'] + 2) // 3),
                  'A signed provider evidence attachment is missing or exceeds its bound.')
        try:
            data = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError('A signed provider evidence attachment is malformed.') from exc
        p.require(len(data) == recorded['bytes'] and p.sha256(data) == recorded['sha256'],
                  'A provider evidence attachment differs from the independent review.')
        check_attachment(data)
    return review, normalized(review, bundle['signature'])


def private_folder(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    else:
        sync_directory(path.parent)
    return protected(path, directory=True, private=True)


@contextmanager
def lock(root, *, shared=False):
    path = root / '.billing.lock'
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if not shared:
        flags |= os.O_CREAT
    with os.fdopen(os.open(path, flags, 0o600), 'rb') as stream:
        info = os.fstat(stream.fileno())
        p.require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, info.st_nlink,
                                                 stat.S_IMODE(info.st_mode)) == (0, 0, 1, 0o600),
                  'Provider billing lock is outside its protected custody.')
        fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        yield


def register(reference, path):
    p.token(reference)
    secret = credential_from(path)
    protected(CREDENTIALS.parent, directory=True)
    directory = private_folder(CREDENTIALS)
    with lock(directory):
        leaf = directory / reference
        if os.path.lexists(leaf):
            p.require(credential_from(leaf) == secret, 'The protected reference already belongs to another credential.')
            return
        with tempfile.TemporaryDirectory(prefix='.credential-', dir=directory) as temporary:
            staged = Path(temporary) / 'key'
            write_private(staged, secret.encode('ascii') + b'\n')
            staged.rename(leaf)
        sync_directory(directory)


def available(secret, review):
    from provider_broker import BrokerExpired, Provider, provider_alarm

    provider = Provider(secret, organization=review['organization'], project=review['project'])
    deadline = time.monotonic() + 15
    try:
        with provider_alarm(deadline, True):
            result = provider.discover(MODEL, deadline)
    except (BrokerExpired, OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
        raise ValueError('The read-only OpenAI account/model check could not complete.') from exc
    p.require(result == 'available', 'OpenAI model access was not verified in the reviewed project (' + result + ').')


def receive(reference, raw):
    p.token(reference)
    secret = credential_from(CREDENTIALS / reference)
    review, proofs = authorize_bundle(raw, reference, secret)
    protected(EVIDENCE.parent, directory=True)
    root = private_folder(EVIDENCE)
    with lock(root):
        folder = private_folder(root / reference)
        digest = review_digest(review)
        destination = folder / digest
        if os.path.lexists(folder / ACTIVE):
            previous = current_digest(folder)
            prior_proofs = proofs_at(folder / previous)
            if previous == digest:
                _, issued = authorize_bundle(retained_bundle(destination), reference, secret)
                p.require(prior_proofs == issued == proofs, 'The issued billing terms changed.')
                return
            prior = p.loads(prior_proofs['context'])['review']
            p.require(review['issued_unix'] > prior['issued_unix'] and
                      all(review[key] == prior[key] for key in ('request', 'organization', 'project')),
                      'Supply a newer independent review for the same credential and project.')
        if not os.path.lexists(destination):
            with os.scandir(folder) as children:
                p.require(sum(1 for _ in islice(children, MAX_REVIEWS + 1)) < MAX_REVIEWS + 1,
                          'The credential evidence directory reached its retention bound.')
        available(secret, review)
        p.require(credential_from(CREDENTIALS / reference) == secret,
                  'The protected credential changed during issuance. Start again.')
        validate_review(review, time.time())
        with tempfile.TemporaryDirectory(prefix='.billing-', dir=folder) as temporary:
            if os.path.lexists(destination):
                _, issued = authorize_bundle(retained_bundle(destination), reference, secret)
                p.require(proofs_at(destination) == issued == proofs,
                          'The staged billing review differs from its receipt.')
            else:
                staged = Path(temporary) / 'terms'
                staged.mkdir(mode=0o700)
                write_private(staged / 'review.bundle', raw)
                for kind, body in proofs.items():
                    write_private(staged / (MODEL + '.' + kind), body)
                sync_directory(staged)
                staged.rename(destination)
                sync_directory(folder)
            marker = Path(temporary) / ACTIVE
            write_private(marker, (digest + '\n').encode('ascii'))
            marker.replace(folder / ACTIVE)
            sync_directory(folder)


def review_bundle(options):
    request = validate_request(p.loads(bounded_file(options.request, REVIEW_LIMIT)))
    sources, evidence = {}, {}
    for kind in SOURCE_KINDS:
        source, path = getattr(options, kind + '_source')
        data = bounded_file(Path(path), EVIDENCE_LIMIT)
        check_attachment(data)
        evidence[kind] = base64.b64encode(data).decode('ascii')
        sources[kind] = {'source': source_id(source), 'sha256': p.sha256(data), 'bytes': len(data)}
    now = int(time.time())
    value = validate_review({'request': request, 'organization': options.organization, 'project': options.project,
        'issued_unix': now, 'expires_unix': options.expires_unix, 'max_context_tokens': options.context_tokens,
        'input_microusd_per_million': options.input_usd_per_million,
        'output_microusd_per_million': options.output_usd_per_million,
        'observed_models': sorted(options.response_model), 'sources': sources}, now)
    signature = openssh('sign', '-f', str(options.signing_key), '-n', NAMESPACE, data=canonical(value))
    p.require(0 < len(signature) <= SIGNATURE_LIMIT, 'The billing review signature exceeds its bound.')
    return canonical({'review': value, 'signature': signature.decode('ascii'), 'evidence': evidence})


def private_output(path, data):
    if path is not None:
        write_private(path, data + b'\n')
        return
    p.require(not sys.stdout.isatty(), 'Write the private billing artifact to a protected file.')
    sys.stdout.buffer.write(data + b'\n')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    stages = parser.add_subparsers(dest='stage', required=True)
    for stage in ('register', 'request', 'receive'):
        command = stages.add_parser(stage)
        command.add_argument('--credential-ref', required=True)
        if stage == 'register':
            command.add_argument('--secret-file', required=True, type=Path)
        elif stage == 'request':
            command.add_argument('--output', type=Path)
        else:
            command.add_argument('--bundle', type=Path)
    review = stages.add_parser('review', description='Sign exact provider terms after reviewing the real scoped project '
        'and credential assignment, the full billable input ceiling, all response model identities and the worst '
        'applicable input/output prices across all authorized models and context lengths. Include ordinary and '
        'cached input, 30-minute and 12-hour cache writes, and all output including reasoning, as applicable. '
        'The approval covers Responses with text, reasoning, local tools, Default service tier, High effort, and '
        'affirms that the reviewed token prices cover all metering under that scope. Keep evidence and the signed '
        'bundle in private custody.')
    review.add_argument('--request', required=True, type=Path)
    review.add_argument('--signing-key', required=True, type=Path)
    review.add_argument('--output', type=Path)
    review.add_argument('--organization', required=True)
    review.add_argument('--project', required=True)
    review.add_argument('--expires-unix', required=True, type=int)
    review.add_argument('--context-tokens', required=True, type=int)
    review.add_argument('--input-usd-per-million', required=True, type=from_usd)
    review.add_argument('--output-usd-per-million', required=True, type=from_usd)
    review.add_argument('--response-model', required=True, action='append')
    for kind in SOURCE_KINDS:
        review.add_argument('--' + kind.replace('_', '-') + '-source', required=True, nargs=2,
                            metavar=('OPENAI_URL_OR_RECORD', 'EVIDENCE_FILE'))
    options = parser.parse_args()
    try:
        if options.stage == 'review':
            private_output(options.output, review_bundle(options))
            return 0
        p.require(os.getuid() == os.geteuid() == 0 and not os.environ.get('SUDO_USER'),
                  'Use the protected root commissioning terminal for provider billing.')
        reference = options.credential_ref
        p.token(reference)
        if options.stage == 'register':
            register(reference, options.secret_file)
            print('Protected credential reference registered.')
        elif options.stage == 'request':
            private_output(options.output, canonical(request_record(reference, credential_from(CREDENTIALS / reference))))
        else:
            if options.bundle is None:
                p.require(not sys.stdin.isatty(), 'Read the signed billing review bundle from protected storage.')
                raw = sys.stdin.buffer.read(BUNDLE_LIMIT + 1)
            else:
                raw = bounded_file(protected(options.bundle, private=True), BUNDLE_LIMIT, owner=0, mode=0o600)
            receive(reference, raw)
            print('Independent billing terms are active. Issuance uses a read-only OpenAI model check.')
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        if type(exc) is ValueError:
            print(str(exc), file=sys.stderr)
        else:
            print('Provider billing setup is blocked by unavailable or unsafe protected inputs.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
