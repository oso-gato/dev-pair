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
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_protocol as p
from ledger_recovery import sync_directory, write_private

CREDENTIALS = Path('/etc/dev-pair/provider-credentials')
EVIDENCE = Path('/etc/dev-pair/provider-evidence')
SIGNERS = Path('/etc/dev-pair/trust/allowed_signers')
MACHINE_ID = Path('/etc/machine-id')
HANDOFF = Path('/root/dev-pair-provider-billing')
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
REVIEWER = 'reviewer.json'
WITHDRAWAL = 'withdrawal.json'
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


def require_broker_release(installed, selected):
    for name in ('provider_billing.py', 'provider_broker.py'):
        baseline = bounded_file(protected(installed / name), 256 * 1024, owner=0)
        candidate = bounded_file(protected(selected / name), 256 * 1024, owner=0)
        p.require(candidate == baseline, 'The selected host broker lacks the installed provider billing controls.')


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


def machine_binding():
    raw = bounded_file(MACHINE_ID, 33)
    p.require(re.fullmatch(rb'[0-9a-f]{32}\n?', raw), 'The VPS machine identity is unavailable.')
    return p.sha256(raw.rstrip(b'\n'))


def reviewer_state():
    path = EVIDENCE / REVIEWER
    if not os.path.lexists(path):
        return None
    state = p.loads(bounded_file(protected(path, private=True), REVIEW_LIMIT, owner=0, mode=0o600))
    p.fields(state, 'schema epoch key fingerprint')
    p.number(state['schema'], 1, 1)
    p.digest(state['epoch'], 32)
    if state['key'] is None:
        p.require(state['fingerprint'] is None, 'Invalid billing signer withdrawal.')
    else:
        p.require(reviewer_key(state['key']) == (state['key'], state['fingerprint']), 'Invalid enrolled billing reviewer.')
    return state


def request_record(reference, secret):
    p.token(reference)
    signer = reviewer_state()
    p.require(signer is None or signer['key'] is not None, 'Independent billing reviewer enrollment was withdrawn.')
    return {'schema': 2, 'machine_sha256': machine_binding(), 'reviewer_epoch': signer['epoch'] if signer else None,
            'credential_ref': reference, 'credential_sha256': fingerprint(secret),
            'profile': PROFILE, 'contract': CONTRACT, 'model': MODEL, 'effort': EFFORT}


def validate_request(row):
    p.require(type(row) is dict, 'Invalid provider billing request.')
    schema = row.get('schema')
    p.number(schema, 1, 2)
    p.fields(row, 'schema credential_ref credential_sha256 profile contract model effort'
             + (' machine_sha256 reviewer_epoch' if schema == 2 else ''))
    if schema == 2:
        p.digest(row['machine_sha256'])
        if row['reviewer_epoch'] is not None:
            p.digest(row['reviewer_epoch'], 32)
    p.token(row['credential_ref'])
    p.digest(row['credential_sha256'])
    p.require((row['profile'], row['contract'], row['model'], row['effort']) == (PROFILE, CONTRACT, MODEL, EFFORT),
              'Billing review targets a different provider contract.')
    return row


def matches_request(row, reference, secret):
    expected = request_record(reference, secret)
    if row['schema'] == 1 and expected['reviewer_epoch'] is None:
        expected.pop('machine_sha256')
        expected.pop('reviewer_epoch')
        expected['schema'] = 1
    return row == expected


def reviewer_key(value):
    p.require(type(value) is str and value.isascii() and len(value) <= 512,
              'Use the independent custodian’s OpenSSH Ed25519 public key.')
    fields = value.split()
    p.require(len(fields) >= 2 and fields[0] == 'ssh-ed25519', 'Use an OpenSSH Ed25519 public key.')
    raw = base64.b64decode(fields[1], validate=True)
    p.require(len(raw) == 51 and raw.startswith(struct.pack('!I', 11) + b'ssh-ed25519' + struct.pack('!I', 32))
              and base64.b64encode(raw).decode() == fields[1], 'The supplied Ed25519 public key is invalid.')
    key_id = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
    return ' '.join(fields[:2]), 'SHA256:' + key_id


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


def signer_rows():
    if not os.path.lexists(SIGNERS):
        return []
    raw = bounded_file(protected(SIGNERS), REVIEW_LIMIT, owner=0)
    return [line for line in raw.splitlines() if line.split() and not line.lstrip().startswith(b'#')]


def other_signer_keys(rows):
    keys = set()
    for row in rows:
        fields = row.split()
        if fields[0] != PRINCIPAL.encode():
            keys.update(right for left, right in zip(fields, fields[1:]) if left == b'ssh-ed25519')
    return keys


def require_distinct_reviewer(key):
    p.require(key.split()[1].encode() not in other_signer_keys(signer_rows()),
              'The provider billing reviewer needs a key separate from other independent authorities.')


def legacy_signers():
    rows = signer_rows()
    used_elsewhere = other_signer_keys(rows)
    # Other OpenSSH principals may use patterns. Only a dedicated, exact
    # previously enrolled billing principal is eligible for this authority.
    return b''.join(line + b'\n' for line in rows if line.split(None, 1)[0] == PRINCIPAL.encode()
                    and not used_elsewhere.intersection(line.split()))


def has_reviewer():
    state = reviewer_state()
    return bool(legacy_signers()) if state is None else state['key'] is not None


def verify_signature(review, signature):
    p.require(type(signature) is str and 0 < len(signature) <= SIGNATURE_LIMIT and signature.isascii() and
              signature.startswith('-----BEGIN SSH SIGNATURE-----\n'), 'Billing review signature is invalid.')
    try:
        state = reviewer_state()
        with tempfile.TemporaryDirectory(prefix='provider-billing-') as directory:
            path = Path(directory) / 'review.sig'
            path.write_text(signature, encoding='ascii')
            signers = Path(directory) / 'allowed_signers'
            if state is None:
                p.require(review['request'].get('reviewer_epoch') is None, 'The enrolled billing reviewer was removed.')
                records = legacy_signers()
                p.require(records, 'The independently enrolled provider billing reviewer is unavailable.')
            else:
                p.require(state['key'] is not None and review['request'].get('reviewer_epoch') == state['epoch'],
                          'The signed terms target a withdrawn or superseded billing reviewer.')
                require_distinct_reviewer(state['key'])
                records = f'{PRINCIPAL} namespaces="{NAMESPACE}" {state["key"]}\n'.encode('ascii')
            write_private(signers, records)
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
    root = reference_directory(reference)
    p.require(review['expires_unix'] > time.time() and current_digest(root) == review_digest(review),
              'The signed billing review expired or was superseded.')
    require_not_withdrawn(root, review)


def validate_send(review, secret):
    assert_current(review)
    reference = review['request']['credential_ref']
    _, retained = validate_proofs(proofs_at(reference_directory(reference) / review_digest(review)), reference)
    p.require(retained == review and matches_request(review['request'], reference, secret),
              'Provider billing authority changed after admission.')


def authority(reference):
    root = reference_directory(reference)
    active = current_digest(root)
    secret = credential_from(CREDENTIALS / reference)
    review, proofs = authorize_bundle(retained_bundle(root / active), reference, secret)
    assert_current(review)
    p.require(review_digest(review) == active and proofs_at(root / active) == proofs,
              'The active billing evidence no longer matches independent review.')
    return {key: review[key] for key in PRICING}, proofs, review


def retained_bundle(directory):
    return bounded_file(protected(directory / 'review.bundle', private=True), BUNDLE_LIMIT, owner=0, mode=0o600)


def json_bundle(raw):
    def reject_pairs(pairs):
        value = dict(pairs)
        p.require(len(value) == len(pairs), 'Duplicate fields in billing review bundle.')
        return value

    try:
        return json.loads(raw, object_pairs_hook=reject_pairs)
    except RecursionError as exc:
        raise ValueError('Billing review bundle exceeds its nesting bound.') from exc


def authorize_bundle(raw, reference, secret):
    p.require(0 < len(raw) <= BUNDLE_LIMIT, 'Billing review bundle is missing or exceeds its bound.')
    bundle = json_bundle(raw)
    p.fields(bundle, 'review signature evidence')
    review = validate_review(bundle['review'], time.time())
    p.require(matches_request(review['request'], reference, secret), 'The review belongs to another credential or host.')
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


def evidence_directory():
    protected(EVIDENCE.parent, directory=True)
    return private_folder(EVIDENCE)


def replace_record(path, value):
    with tempfile.TemporaryDirectory(prefix='.billing-record-', dir=path.parent) as temporary:
        staged = Path(temporary) / 'record'
        write_private(staged, canonical(value))
        staged.replace(path)
        sync_directory(path.parent)


@contextmanager
def trust_lock():
    from bootstrap import Blocked, Bootstrap

    try:
        with Bootstrap().lock('signer-trust.lock'):
            yield
    except Blocked as exc:
        raise ValueError('Protected signer custody is unavailable or an update is in progress.') from exc


def set_reviewer(public, expected_fingerprint, expected_state):
    from provider_transition import Fence

    if public is not None:
        public, actual = reviewer_key(public)
        p.require(actual == expected_fingerprint, 'The key differs from the independently authenticated billing fingerprint.')
        require_distinct_reviewer(public)
    prior = reviewer_state()
    p.require(prior == expected_state or prior is not None and
              (prior['key'], prior['fingerprint']) == (public, expected_fingerprint),
              'Billing reviewer custody changed. Reinspect the independent fingerprint.')
    return Fence().change('reviewer', {'public': public, 'fingerprint': expected_fingerprint, 'expected': expected_state})


def _set_reviewer(public, expected_fingerprint, expected_state):
    state = {'schema': 1, 'epoch': uuid.uuid4().hex, 'key': None, 'fingerprint': None}
    if public is not None:
        public, actual = reviewer_key(public)
        p.require(actual == expected_fingerprint, 'The key differs from the independently authenticated billing fingerprint.')
        state.update(key=public, fingerprint=actual)
    root = evidence_directory()
    with trust_lock(), lock(root):
        if public is not None:
            require_distinct_reviewer(public)
        prior = reviewer_state()
        if prior is not None and (prior['key'], prior['fingerprint']) == (state['key'], state['fingerprint']):
            return prior
        p.require(prior == expected_state, 'Billing reviewer custody changed. Reinspect the independent fingerprint.')
        replace_record(root / REVIEWER, state)
    return state


def withdrawal(root):
    path = root / WITHDRAWAL
    if not os.path.lexists(path):
        return 0, None
    data = p.loads(bounded_file(protected(path, private=True), 256, owner=0, mode=0o600))
    p.fields(data, 'schema withdrawn_unix review_sha256')
    p.number(data['schema'], 1, 1)
    p.number(data['withdrawn_unix'], 1, 2**63 - 1)
    if data['review_sha256'] is not None:
        p.digest(data['review_sha256'])
    return data['withdrawn_unix'], data['review_sha256']


def require_not_withdrawn(root, review):
    cutoff, digest = withdrawal(root)
    p.require(review['issued_unix'] > cutoff and review_digest(review) != digest,
              'The signed billing review was withdrawn.')


def withdraw_reference(reference):
    from provider_transition import Fence

    reference_directory(reference)
    return Fence().change('withdraw-reference', {'reference': reference})


def _withdraw_reference(reference):
    root = evidence_directory()
    with lock(root):
        folder = reference_directory(reference)
        previous, old_digest = withdrawal(folder)
        when = max(int(time.time()), previous)
        current = current_digest(folder) if os.path.lexists(folder / ACTIVE) else old_digest
        replace_record(folder / WITHDRAWAL, {'schema': 1, 'withdrawn_unix': when, 'review_sha256': current})
        return when


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
        try:
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('A protected billing update or provider admission is in progress. Retry this action.') from exc
        yield


def register(reference, path):
    register_secret(reference, credential_from(path))


def register_secret(reference, secret):
    p.token(reference)
    p.require(type(secret) is str and secret.isascii(), 'A scoped OpenAI project or service-account API key is required.')
    credential(secret.encode('ascii'))
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
    from provider_transition import Fence

    p.token(reference)
    secret = credential_from(CREDENTIALS / reference)
    receive_candidate(reference, secret, raw, EVIDENCE / reference)
    return Fence().change('receive', {'reference': reference, 'data': base64.b64encode(raw).decode('ascii')})


def receive_candidate(reference, secret, raw, folder):
    review, proofs = authorize_bundle(raw, reference, secret)
    digest = review_digest(review)
    destination = folder / digest
    if os.path.lexists(folder):
        protected(folder, directory=True, private=True)
        require_not_withdrawn(folder, review)
        if os.path.lexists(folder / ACTIVE):
            previous = current_digest(folder)
            prior_proofs = proofs_at(folder / previous)
            if previous == digest:
                _, issued = authorize_bundle(retained_bundle(destination), reference, secret)
                p.require(prior_proofs == issued == proofs, 'The issued billing terms changed.')
                return review, proofs, destination, True
            prior = p.loads(prior_proofs['context'])['review']
            p.require(review['issued_unix'] > prior['issued_unix'] and
                      all(review[key] == prior[key] for key in ('organization', 'project')) and
                      all(review['request'][key] == prior['request'][key] for key in ('credential_ref', 'credential_sha256')),
                      'Supply a newer independent review for the same credential and project.')
        if not os.path.lexists(destination):
            with os.scandir(folder) as children:
                p.require(sum(1 for _ in islice(children, MAX_REVIEWS + 1)) < MAX_REVIEWS + 1,
                          'The credential evidence directory reached its retention bound.')
    return review, proofs, destination, False


def _receive(reference, raw):
    p.token(reference)
    secret = credential_from(CREDENTIALS / reference)
    root = evidence_directory()
    with lock(root):
        folder = private_folder(root / reference)
        review, proofs, destination, issued = receive_candidate(reference, secret, raw, folder)
        if issued:
            return
        digest = destination.name
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


def setup_handoff(reference):
    secret = credential_from(CREDENTIALS / reference)
    protected(HANDOFF.parent, directory=True)
    root = private_folder(HANDOFF)
    output = root / (reference + '.request.json')
    bundle = root / (reference + '.review.bundle')
    with lock(root):
        request = request_record(reference, secret)
        if not os.path.lexists(output) or p.loads(bounded_file(protected(output, private=True), REVIEW_LIMIT,
                                                               owner=0, mode=0o600)) != request:
            replace_record(output, request)
    return output, bundle


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
