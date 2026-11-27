#!/usr/bin/env python3
"""Observe the fixed private checklist journey and assemble D's independent receipt."""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from bootstrap import Blocked, Bootstrap, checked_file, relay
from release_trust import DIGEST, SHA, require

SIGNERS = '/etc/dev-pair/destination-observer/allowed_signers'
NAMESPACE = 'dev-pair-destination-observation'
FINAL_NAMESPACE = 'dev-pair-destination'
FAMILIES = {'ipv4': socket.AF_INET, 'ipv6': socket.AF_INET6}
TAILNETS = {4: ipaddress.ip_network('100.64.0.0/10'), 6: ipaddress.ip_network('fd7a:115c:a1e0::/48')}
VANTAGES = ('authorized', 'denied', 'public', 'provider', 'controller')
NAME = r'[A-Za-z0-9@._:+/-]{1,128}'
JOB = r'[a-z0-9][a-z0-9-]{0,47}'
DNS = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}ts\.net'
HOST = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}'
IMAGE = r'ghcr\.io/oso-gato/dev-pair/checklist@sha256:' + DIGEST
LIFETIME = 1800
PAIR_WINDOW = 120
MAX_RECORD = 32768
TIMEOUT = 5
EVENTS = {
    'restart': 'controller', 'reboot': 'provider', 'clean-restore': 'controller',
    'tailnet-loss': 'provider', 'tailnet-restored': 'provider', 'rollback': 'controller', 're-promote': 'controller',
}
CONTINUITY = {
    'restart-same-item': 'restart', 'reboot-same-item': 'reboot',
    'clean-restore-same-item': 'clean-restore', 'tailnet-recovery-app': 'tailnet-restored',
    'rollback-same-item': 'rollback',
}
NATIVE = {'browser-add-and-complete', 'unauthorized-app', 'public-app', *CONTINUITY}
BASE = {'version', 'source_sha', 'machine_id', 'boot_id', 'issued_at', 'expires_at'}
PLAN = BASE | {'kind', 'job_id', 'ceremony_id', 'dns_name', 'provider_recovery',
               'public_addresses', 'clients'}
RELEASE = {'release_source', 'image', 'publisher_run_id', 'publisher_run_attempt',
           'guard_sha256', 'tailnet_addresses', 'negative_routes', 'rollback_image'}
ACCESS = {'node_id', 'tailnet', 'keys_sha256', 'acl_sha256', 'execution_route'}
SITE = {'version', 'kind', 'dns_name', 'provider_recovery', 'public_addresses', 'clients'}
SITE_RELEASE = {'negative_routes', 'tailnet_addresses'}
BINDING = {'version', 'kind', 'job_id', 'source_sha', 'machine_id', 'boot_id', 'dns_name',
           'provider_recovery', 'public_addresses'}
BINDING_RELEASE = RELEASE - SITE_RELEASE


def encoding(data):
    return (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def keys(data, expected):
    require(type(data) is dict and set(data) == expected, 'incorrect observation record fields')


def canonical_uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def address(value, family):
    result = ipaddress.ip_address(value)
    require(type(value) is str and str(result) == value and result.version == (4 if family == 'ipv4' else 6)
            and not (result.is_unspecified or result.is_multicast or result.is_loopback),
            'address does not match the selected family')
    return result


def bounded_file(path, maximum=MAX_RECORD):
    with open_regular(path) as file:
        require(os.fstat(file.fileno()).st_size <= maximum, 'observation input exceeds its size bound')
        data = file.read(maximum + 1)
    require(0 < len(data) <= maximum, 'observation input is empty or exceeds its size bound')
    return data


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Blocked('observation input must be a regular file')
    return os.fdopen(fd, 'rb')


def state_dir(path):
    require(path.is_absolute() and path == path.resolve(), 'observation directory must be canonical and absolute')
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            'observation directory must be privately owned by the named client')
    for parent in path.parents:
        info = parent.stat()
        require(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022,
                'observation directory ancestry must be protected')
    return path


def write_once(path, message):
    """Publish complete bytes with a no-replace link and directory fsync."""
    if os.path.lexists(path):
        require(bounded_file(path) == message, 'existing observation differs from retained evidence')
        return
    with tempfile.NamedTemporaryFile(dir=path.parent) as stream:
        stream.write(message)
        stream.flush()
        os.fsync(stream.fileno())
        os.link(stream.name, path, follow_symlinks=False)
        fd = os.open(path.parent, os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def record_name(test, family):
    return test + '--' + family + '.json'


def verify_file(path, principal, signers=SIGNERS, namespace=NAMESPACE):
    payload = bounded_file(path)
    signature = bounded_file(path.with_name(path.name + '.sig'), 16384)
    with tempfile.TemporaryFile() as original:
        original.write(signature)
        original.flush()
        result = subprocess.run(
            ['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', principal,
             '-n', namespace, '-s', f'/proc/self/fd/{original.fileno()}'],
            input=payload, capture_output=True, pass_fds=(original.fileno(),), timeout=10,
            env={'PATH': '/usr/bin', 'LC_ALL': 'C'}, check=False)
    require(result.returncode == 0, 'invalid independent signature for ' + principal)
    return json.loads(payload, object_pairs_hook=relay.unique), digest(payload)


def validate_plan(plan, now):
    require(type(plan) is dict and plan.get('kind') in {'checklist-release', 'access-cutover'},
            'unsupported destination observation plan')
    checklist = plan['kind'] == 'checklist-release'
    keys(plan, PLAN | (RELEASE if checklist else ACCESS))
    require(type(plan['version']) is int and plan['version'] == 1
            and matches(SHA, plan['source_sha']) and matches(r'[0-9a-f]{32}', plan['machine_id'])
            and canonical_uuid(plan['boot_id']) and canonical_uuid(plan['ceremony_id'])
            and matches(JOB, plan['job_id']) and matches(DNS, plan['dns_name'])
            and matches(r'hostinger://[A-Za-z0-9_-]{1,100}/recovery', plan['provider_recovery']),
            'observation plan does not select the exact destination and operation')
    require(type(plan['issued_at']) is int and type(plan['expires_at']) is int
            and plan['issued_at'] <= now < plan['expires_at'] <= plan['issued_at'] + LIFETIME,
            'observation plan is outside its 30-minute independent execution window')
    keys(plan['clients'], set(VANTAGES))
    require(all(matches(NAME, value) for value in plan['clients'].values())
            and len(set(plan['clients'].values())) == len(VANTAGES), 'named vantages must have distinct identities')
    keys(plan['public_addresses'], set(FAMILIES))
    for family, value in plan['public_addresses'].items():
        Bootstrap.public_probe_host(value, family, plan['provider_recovery'])
    if not checklist:
        require(all(matches(DIGEST, plan[field]) for field in ('keys_sha256', 'acl_sha256'))
                and matches(NAME, plan['node_id']) and matches(NAME, plan['tailnet'])
                and plan['execution_route'] in ('tailnet-core', 'provider-recovery'),
                'access plan lacks checked node, key and ACL information')
        return
    require(matches(SHA, plan['release_source']) and matches(IMAGE, plan['image'])
            and matches(DIGEST, plan['guard_sha256'])
            and (plan['rollback_image'] is None or matches(IMAGE, plan['rollback_image']) and plan['rollback_image'] != plan['image'])
            and all(type(plan[key]) is int and plan[key] > 0 for key in ('publisher_run_id', 'publisher_run_attempt')),
            'observation plan lacks the exact release and publisher attempt')
    keys(plan['tailnet_addresses'], set(FAMILIES))
    keys(plan['negative_routes'], {'denied', 'public'})
    for family, value in plan['tailnet_addresses'].items():
        remote = address(value, family)
        require(remote in TAILNETS[remote.version], 'selected checklist address is outside Tailscale')
    for vantage, routes in plan['negative_routes'].items():
        keys(routes, set(FAMILIES))
        for family, route in routes.items():
            if vantage == 'public' and plan['public_addresses'][family] is None:
                require(route is None, 'absent provider address needs external provider evidence')
                continue
            keys(route, {'source_address', 'control_address', 'control_dns'})
            source = address(route['source_address'], family)
            control = address(route['control_address'], family)
            require((source in TAILNETS[source.version]) == (vantage == 'denied')
                    and (vantage != 'public' or control.is_global)
                    and matches(HOST, route['control_dns']) and route['control_dns'] != plan['dns_name']
                    and str(control) not in (plan['tailnet_addresses'][family], plan['public_addresses'][family]),
                    'negative vantage requires its own admitted source and independent HTTPS control')


def probe_plan(plan):
    if plan['kind'] == 'access-cutover':
        return Bootstrap.access_probe_plan(plan['dns_name'], plan['provider_recovery'], plan['public_addresses'])
    expected = {}
    dns = plan['dns_name']
    endpoint = f'https://{dns}/'
    for family in FAMILIES:
        value = plan['public_addresses'][family]
        public = Bootstrap.public_probe_host(value, family, plan['provider_recovery'])
        expected['public-app', family] = (f'https://{public}:443/' if value is not None else public, 'public', 'deny')
        expected['remote-root', family] = (f'ssh://root@{dns}:22', 'authorized', 'deny')
        expected['unauthorized-app', family] = (endpoint, 'denied', 'deny')
        expected['tailnet-loss-app', family] = (endpoint, 'authorized', 'deny')
        for name in ('browser-add-and-complete', *CONTINUITY):
            if name != 'rollback-same-item' or plan['rollback_image'] is not None:
                expected[name, family] = (endpoint, 'authorized', 'allow')
    return expected


def export_release(job):
    """Read the normal J/D records on the destination under D's release lock."""
    from destination_release import Destination
    from product_release import matches as matching_release, record, trusted_directory, product

    require(os.geteuid() == 0 and matches(JOB, job), 'use the admitted destination controller and exact job ID')
    destination = Destination()
    with destination.release_gate() as (setup, _, dns):
        promotion = record(trusted_directory(product.job_path(job)))
        activation = destination.initial_activation()
        require(promotion and promotion['job_id'] == job and promotion['phase'] == 'awaiting-independent-destination'
                and matching_release(activation['active'], promotion['release'], promotion['binding'])
                and not activation['pending'] and not activation['route_pending']
                and destination.serve_config(dns), 'selected exact release is not awaiting independent destination checks')
        live = activation['active']
        previous = activation['previous']
        cutover = destination.verify_final_guard()
        return {'version': 1, 'kind': 'checklist-release', 'job_id': job, 'source_sha': setup['platform_sha'],
                **destination.destination_identity(), 'dns_name': dns, 'provider_recovery': cutover['provider_recovery'],
                'public_addresses': cutover['public_addresses'], 'guard_sha256': cutover['guard_sha256'],
                'release_source': live['source_sha'], 'image': live['subject'], 'publisher_run_id': live['run_id'],
                'publisher_run_attempt': live['run_attempt'],
                'rollback_image': previous['subject'] if previous and previous.get('verified_destination') else None}


def prepare_plan(binding, site, now, previous):
    require(type(binding) is dict and binding.get('kind') in ('access-cutover', 'checklist-release'),
            'unsupported protected destination binding')
    checklist = binding['kind'] == 'checklist-release'
    keys(site, SITE | (SITE_RELEASE if checklist else ACCESS))
    keys(binding, BINDING | (BINDING_RELEASE if checklist else set()))
    require(all(binding[key] == site[key] for key in BINDING & SITE),
            'destination binding differs from independently admitted site endpoints')
    clocks = {key: previous[key] for key in ('issued_at', 'expires_at', 'ceremony_id')} if previous else {
        'issued_at': now, 'expires_at': now + LIFETIME, 'ceremony_id': str(uuid.uuid4())}
    plan = {**site, **binding, **clocks}
    validate_plan(plan, now)
    require(previous is None or previous == plan, 'retained plan differs from the protected release or site profile')
    return plan


def title_for(plan, family):
    return f"Dev-pair release observation {plan['ceremony_id']} {family}"


def browser_item(origin, remote, title, *, add, sandbox=True, browser_path=None):
    """Perform the deployed page's normal user actions through a fresh browser."""
    from playwright.sync_api import sync_playwright

    host = urlsplit(origin).hostname
    chromium = browser_path or next((path for path in ('/usr/bin/chromium', '/usr/bin/chromium-browser')
                                    if Path(path).is_file()), None)
    require(chromium is not None, 'the independently managed Chromium package is unavailable')
    resolver_ip = f'[{remote}]' if ':' in remote else remote
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=chromium, chromium_sandbox=sandbox,
            args=['--no-proxy-server', '--disable-quic', '--disable-background-networking',
                  f'--host-resolver-rules=MAP {host} {resolver_ip}, MAP * ~NOTFOUND'])
        page = browser.new_page(service_workers='block', accept_downloads=False)
        page.set_default_timeout(5000)
        write = {}

        def scope_request(route):
            request = route.request
            if request.method == 'GET' and request.url in (origin, origin + 'items'):
                route.continue_()
            elif request.method == 'POST' and request.url in write:
                payload = write.pop(request.url)
                if (payload is None and request.post_data is None) or (payload is not None and request.post_data_json == payload):
                    route.continue_()
                else:
                    route.abort()
            else:
                route.abort()

        page.route('**/*', scope_request)

        def app_response(response, path, status):
            peer = response.server_addr() if response else None
            require(response and response.url == origin + path and response.status == status and peer
                    and ipaddress.ip_address(peer['ipAddress']) == ipaddress.ip_address(remote),
                    'browser did not get the expected checklist reply on the selected address')
            return response

        def await_reply(path, method):
            return page.expect_response(lambda response: response.url == origin + path
                                        and response.request.method == method)

        def app_json(response):
            length = response.headers.get('content-length', '')
            require(length.isdecimal() and int(length) <= 1024**2, 'checklist HTTP body exceeds its observed bound')
            return response.json()

        with await_reply('items', 'GET') as inventory:
            homepage = page.goto(origin, wait_until='domcontentloaded', timeout=5000)
        app_response(homepage, '', 200)
        records = app_json(app_response(inventory.value, 'items', 200))
        require(type(records) is list and len(records) <= 1000 and all(type(item) is dict for item in records),
                'unexpected checklist inventory response')
        selected = [item for item in records if item.get('title') == title]
        require(len(selected) <= 1, 'observation item is duplicated')
        listing = page.get_by_role('list', name='Checklist items')
        status = {'page': homepage.status, 'inventory': inventory.value.status, 'peer': remote}
        if add and not selected:
            page.get_by_role('textbox', name='Item title').fill(title)
            write[origin + 'items'] = {'title': title}
            with await_reply('items', 'POST') as added:
                page.get_by_role('button', name='Add', exact=True).click()
            selected = [app_json(app_response(added.value, 'items', 201))]
            status['added'] = 201
        require(len(selected) == 1, 'completed ceremony item is missing from the actual checklist')
        item = selected[0]
        require(item.get('title') == title and type(item.get('id')) is int and 0 < item['id'] < 2**63
                and type(item.get('done')) is bool, 'browser response lacks exact checklist item identity')
        row = listing.get_by_role('listitem').filter(has=page.get_by_text(title, exact=True))
        if add and not item['done']:
            path = f"items/{item['id']}/complete"
            write[origin + path] = None
            with await_reply(path, 'POST') as completed:
                row.get_by_role('button', name='Complete ' + title).click()
            require(app_json(app_response(completed.value, path, 200)) == {**item, 'done': True},
                    'completed checklist reply refers to a different item')
            status['completed'] = 200
        elif not add:
            require(item['done'] is True, 'reconnected checklist item is not complete')
        row.get_by_text('Done', exact=True).wait_for()
        return {**status, 'item_id': item['id'], 'item_title_sha256': digest(title.encode())}


def system_trust():
    paths = ssl.get_default_verify_paths()
    candidates = ('/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/certs/ca-certificates.crt', paths.openssl_cafile)
    bundle = next((path for path in candidates if path and Path(path).is_file()), None)
    require(bundle is not None, 'the managed system CA bundle is unavailable')
    return ssl.create_default_context(cafile=bundle)


def https_status(host, remote, family, source, *, port=443, tls=None):
    """One direct HTTPS request, with fixed origin and no redirects or inherited proxies."""
    with socket.socket(FAMILIES[family], socket.SOCK_STREAM) as connection:
        connection.settimeout(TIMEOUT)
        connection.bind((source, 0))
        try:
            connection.connect((remote, port))
        except ConnectionRefusedError:
            return 'connection-refused'
        except TimeoutError:
            return 'connect-timeout'
        with (tls or system_trust()).wrap_socket(connection, server_hostname=host) as secured:
            secured.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode('ascii'))
            response = http.client.HTTPResponse(secured, method='GET')
            try:
                response.begin()
                return response.status
            finally:
                response.close()


def denied_request(host, remote, family, route, *, request=https_status):
    source = route['source_address']
    control_host, control_ip = route['control_dns'], route['control_address']
    before = request(control_host, control_ip, family, source)
    require(before in (200, 204), 'the negative vantage does not have its admitted healthy HTTPS control')
    target = request(host, remote, family, source)
    after = request(control_host, control_ip, family, source)
    require(after in (200, 204), 'the negative vantage lost its admitted HTTPS control')
    require(target in (401, 403, 'connection-refused', 'connect-timeout'),
            'negative client did not observe the expected scoped checklist denial')
    return {'peer': remote, 'source_address': source, 'target': target, 'control_peer': control_ip,
            'control_before': before, 'control_after': after}


def make_probe(plan, plan_sha, test, family, expected, method, evidence, now):
    endpoint, vantage, outcome = expected[test, family]
    require(plan['issued_at'] <= now < plan['expires_at'], 'the observation ran outside its admitted window')
    return {'version': 1, 'plan_sha256': plan_sha, 'test': test, 'family': family, 'endpoint': endpoint,
            'vantage': vantage, 'client_id': plan['clients'][vantage], 'outcome': outcome,
            'observed_at': now, 'method': method, 'evidence': evidence}


def observe(plan, plan_sha, test, family, directory, expected):
    import fcntl

    require(plan['kind'] == 'checklist-release' and test in NATIVE and (test, family) in expected,
            'this check needs its separately authorized observation')
    path = directory / record_name(test, family)
    with os.fdopen(os.open(directory / '.collect.lock', os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if path.exists():
            saved = json.loads(bounded_file(path), object_pairs_hook=relay.unique)
            require(saved.get('plan_sha256') == plan_sha, 'use the evidence directory admitted for this ceremony')
            return path
        dns = plan['dns_name']
        if test in ('unauthorized-app', 'public-app'):
            vantage = expected[test, family][1]
            remote = plan['public_addresses' if vantage == 'public' else 'tailnet_addresses'][family]
            require(remote is not None, 'provider address absence requires an independent provider observation')
            method = 'direct-verified-https'
            detail = denied_request(dns, remote, family, plan['negative_routes'][vantage][family])
        else:
            from playwright.sync_api import Error as BrowserError

            method = 'checklist-browser'
            initial = test == 'browser-add-and-complete'
            peer = plan['tailnet_addresses'][family]
            try:
                detail = browser_item(f'https://{dns}/', peer, title_for(plan, family if initial else 'ipv4'), add=initial)
            except BrowserError as exc:
                raise Blocked('the managed browser could not observe the exact checklist page, form or item') from exc
            if initial:
                require(detail.get('added') == 201 and detail.get('completed') == 200,
                        'the ceremony item exists; recover the original add/complete observation before signing')
        record = make_probe(plan, plan_sha, test, family, expected, method, detail, int(time.time()))
        write_once(path, encoding(record))
    return path


def observer_principal(vantage):
    return 'dev-pair-observer-' + vantage


def configured_signers():
    path = checked_file(SIGNERS)
    principals, public_keys = set(), set()
    permitted = {observer_principal(actor) for actor in (*VANTAGES, 'plan')}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = line.split()
        require(len(fields) >= 4 and fields[0] in permitted and fields[0] not in principals
                and fields[1] == f'namespaces="{NAMESPACE}"' and fields[2] in ('ssh-ed25519', 'sk-ssh-ed25519@openssh.com')
                and fields[3] not in public_keys, 'observation trust requires one separate key per fixed principal')
        principals.add(fields[0])
        public_keys.add(fields[3])
    require(principals == permitted, 'all observation principals must have separately admitted keys')
    return path


def external_method(plan, test, family):
    if plan['kind'] == 'access-cutover':
        return 'independent-access-session'
    if test == 'remote-root':
        return 'independent-openssh-session'
    if test == 'tailnet-loss-app':
        return 'independent-tailnet-loss-session'
    if test == 'public-app' and plan['public_addresses'][family] is None:
        return 'provider-address-absence'
    raise Blocked('this check can be issued only by its fixed native collector')


def external_probe(plan, plan_sha, test, family, expected, transcript, now):
    require((test, family) in expected, 'the external check is outside the admitted ceremony')
    method = external_method(plan, test, family)
    return make_probe(plan, plan_sha, test, family, expected, method,
                      {'transcript_sha256': digest(transcript)}, now)


def event_record(plan, plan_sha, event, before, after, transcript, now):
    require(plan['kind'] == 'checklist-release' and event in EVENTS
            and plan['issued_at'] <= now < plan['expires_at'], 'event is outside the admitted release ceremony')
    require(matches(NAME, before) and matches(NAME, after) and before != after,
            'the controlled event needs separately observed before and after identities')
    if event in ('restart', 'reboot'):
        require(canonical_uuid(before) and canonical_uuid(after), 'restart/reboot requires observed invocation/boot identities')
    if event == 'reboot':
        require(before == plan['boot_id'], 'boot event did not begin on the admitted boot')
    if event in ('rollback', 're-promote'):
        wanted = (plan['image'], plan['rollback_image']) if event == 'rollback' else (plan['rollback_image'], plan['image'])
        require((before, after) == wanted, 'event does not identify the selected and previous verified OCI releases')
    if event in ('tailnet-loss', 'tailnet-restored'):
        wanted = ('private-reachable', 'private-unreachable') if event == 'tailnet-loss' else ('private-unreachable', 'private-reachable')
        require((before, after) == wanted, 'event does not describe the actual intended tailnet transition')
    vantage = EVENTS[event]
    return {'version': 1, 'plan_sha256': plan_sha, 'event': event, 'vantage': vantage,
            'client_id': plan['clients'][vantage], 'observed_at': now, 'before': before, 'after': after,
            'transcript_sha256': digest(transcript)}


def event_check(record, plan, plan_sha, event):
    keys(record, {'version', 'plan_sha256', 'event', 'vantage', 'client_id',
                  'observed_at', 'before', 'after', 'transcript_sha256'})
    reconstructed = event_record(plan, plan_sha, event, record['before'], record['after'],
                                 b'validated separately retained transcript', record['observed_at'])
    reconstructed['transcript_sha256'] = record['transcript_sha256']
    require(record == reconstructed and type(record['version']) is int and type(record['observed_at']) is int
            and matches(DIGEST, record['transcript_sha256']), 'controlled event evidence does not bind this plan')
    return record


def check_probe(plan, plan_sha, record, test, family, expected):
    keys(record, {'version', 'plan_sha256', 'test', 'family', 'endpoint', 'vantage',
                  'client_id', 'outcome', 'observed_at', 'method', 'evidence'})
    require(type(record['version']) is int and type(record['observed_at']) is int
            and record == make_probe(plan, plan_sha, test, family, expected, record['method'],
                                     record['evidence'], record['observed_at']),
            'observation is not bound to its admitted plan, test and client')
    detail = record['evidence']
    if test in ('browser-add-and-complete', *CONTINUITY) and plan['kind'] == 'checklist-release':
        initial = test == 'browser-add-and-complete'
        keys(detail, {'page', 'inventory', 'peer', 'item_id', 'item_title_sha256'}
             | ({'added', 'completed'} if initial else set()))
        require(record['method'] == 'checklist-browser' and detail['page'] == detail['inventory'] == 200
                and (not initial or (detail['added'], detail['completed']) == (201, 200))
                and detail['peer'] == plan['tailnet_addresses'][family]
                and type(detail['item_id']) is int and 0 < detail['item_id'] < 2**63
                and detail['item_title_sha256'] == digest(title_for(plan, family if initial else 'ipv4').encode()),
                'browser observation lacks the exact successful checklist journey or same-item read')
    elif plan['kind'] == 'checklist-release' and (test == 'unauthorized-app' or
           test == 'public-app' and plan['public_addresses'][family] is not None):
        vantage = expected[test, family][1]
        route = plan['negative_routes'][vantage][family]
        remote = plan['public_addresses' if vantage == 'public' else 'tailnet_addresses'][family]
        keys(detail, {'peer', 'source_address', 'target', 'control_peer', 'control_before', 'control_after'})
        require(record['method'] == 'direct-verified-https' and detail['peer'] == remote
                and detail['source_address'] == route['source_address'] and detail['control_peer'] == route['control_address']
                and detail['target'] in (401, 403, 'connection-refused', 'connect-timeout')
                and detail['control_before'] in (200, 204) and detail['control_after'] in (200, 204),
                'negative observation lacks actual selected denial and independent healthy controls')
    else:
        keys(detail, {'transcript_sha256'})
        require(record['method'] == external_method(plan, test, family) and matches(DIGEST, detail['transcript_sha256']),
                'external access observation lacks its independently retained transcript')
    return record


def check_release_sequence(plan, observations, events, now):
    original = observations['browser-add-and-complete', 'ipv4']['evidence']
    second = observations['browser-add-and-complete', 'ipv6']['evidence']
    require(original['item_id'] != second['item_id'], 'both families must actually add and complete their own item')
    times = {name: event['observed_at'] for name, event in events.items()}
    require(max(observations['browser-add-and-complete', family]['observed_at']
                for family in FAMILIES) < times['restart'] < times['reboot'] < times['clean-restore']
            < times['tailnet-loss'] < times['tailnet-restored'] <= now,
            'independent recovery events lack the required observed sequence')
    if plan['rollback_image'] is not None:
        require(times['clean-restore'] < times['rollback'] < times['re-promote'] < times['tailnet-loss'],
                'rollback proof does not belong to the admitted recovery sequence')
    for family in FAMILIES:
        for test, event in CONTINUITY.items():
            if event not in times:
                continue
            reading = observations[test, family]
            next_events = [stamp for stamp in times.values() if stamp > times[event]]
            require(times[event] < reading['observed_at'] < min(next_events, default=now + 1)
                    and reading['evidence']['item_id'] == original['item_id'],
                    'continuity observation did not reconnect to the original completed item in its event window')
        lost = observations['tailnet-loss-app', family]['observed_at']
        require(times['tailnet-loss'] < lost < times['tailnet-restored'],
                'loss check was not observed during the independently recorded interruption')
        recovered = observations['tailnet-recovery-app', family]['observed_at']
        for test in ('unauthorized-app', 'public-app', 'remote-root'):
            denied_at = observations[test, family]['observed_at']
            require(times['tailnet-restored'] < denied_at <= now and abs(denied_at - recovered) <= PAIR_WINDOW,
                    'the negative observations need a contemporaneous healthy authorized family control')
    return original, events['reboot']['after']


def check_access_recovery(observations):
    reopened = observations['reopened-recovery', 'provider']['observed_at']
    during = observations['recovery-during-loss', 'provider']['observed_at']
    lost = [observations[test, family]['observed_at'] for family in FAMILIES
            for test in ('lost-ssh', 'lost-mosh', 'maintenance-lost', 'development-lost')]
    restored = [observations[test, family]['observed_at'] for family in FAMILIES
                for test in ('restored-ssh', 'maintenance-restored', 'development-restored')]
    require(reopened < min(during, *lost) and max(during, *lost) < min(restored),
            'access observations must reopen independent recovery before loss and restore private access afterward')


def assembled_receipt(plan, plan_sha, directory, *, now, verify):
    expected = probe_plan(plan)
    data = {key: plan[key] for key in ('version', 'source_sha', 'machine_id', 'boot_id', 'dns_name')}
    data.update(issued_at=now, expires_at=min(plan['expires_at'], now + LIFETIME))
    require(now < data['expires_at'], 'the independent observation plan has expired')
    observations, rows = {}, []
    for (test, family), (_, vantage, _) in sorted(expected.items()):
        if plan['kind'] == 'checklist-release' and test == 'public-app' and plan['public_addresses'][family] is None:
            signer = observer_principal('provider')
        else:
            signer = observer_principal(vantage)
        path = directory / record_name(test, family)
        require(path.exists(), f'waiting for independent observation {test}/{family}')
        raw, proof_hash = verify(path, signer)
        row = check_probe(plan, plan_sha, raw, test, family, expected)
        require(row['observed_at'] <= now, 'observation time is in the future')
        observations[test, family] = row
        rows.append({key: row[key] for key in ('test', 'family', 'endpoint', 'vantage',
                                               'client_id', 'outcome', 'observed_at')})
        rows[-1]['evidence_sha256'] = proof_hash
    Bootstrap().verify_access_probes({**data, 'probes': rows}, expected)
    data['probes'] = rows
    if plan['kind'] == 'access-cutover':
        check_access_recovery(observations)
        data.update({key: plan[key] for key in ACCESS | {'provider_recovery', 'public_addresses'}})
    else:
        events = {}
        for event, vantage in EVENTS.items():
            if event in ('rollback', 're-promote') and plan['rollback_image'] is None:
                continue
            path = directory / record_name(event, 'event')
            require(path.exists(), f'waiting for independently exercised {event}')
            record, _ = verify(path, observer_principal(vantage))
            events[event] = event_check(record, plan, plan_sha, event)
        item, boot = check_release_sequence(plan, observations, events, now)
        data.update(boot_id=boot, item_id=item['item_id'], item_title_sha256=item['item_title_sha256'],
                    release_source=plan['release_source'], image=plan['image'], guard_sha256=plan['guard_sha256'])
    require(len(encoding(data)) <= 16384, 'D receipt exceeds its protected input limit')
    return data


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, help='independently signed observation plan')
    parser.add_argument('--directory', type=Path, help='private evidence directory for this ceremony')
    stages = parser.add_subparsers(dest='stage', required=True)
    export = stages.add_parser('export-release', help='read the exact settled release from protected J/D state')
    export.add_argument('job')
    begin = stages.add_parser('begin', help='prepare a plan from the admitted site profile and observed destination binding')
    begin.add_argument('--binding', type=Path, required=True)
    begin.add_argument('--site', type=Path, required=True)
    collect = stages.add_parser('collect', help='exercise the fixed browser or direct HTTPS check')
    external = stages.add_parser('record-access', help='record a separately authorized observed access transcript')
    for stage in (collect, external):
        stage.add_argument('test')
        stage.add_argument('family', choices=(*FAMILIES, 'provider'))
    event = stages.add_parser('record-event', help='record a separately operated recovery transition')
    event.add_argument('event', choices=EVENTS)
    event.add_argument('--before', required=True)
    event.add_argument('--after', required=True)
    for stage in (event, external):
        stage.add_argument('--transcript', type=Path, required=True)
        stage.add_argument('--observed-at', type=int, required=True)
    stages.add_parser('assemble', help='assemble a D receipt from complete separately signed observations')
    return parser.parse_args()


def main():
    args = arguments()
    try:
        if args.stage == 'export-release':
            sys.stdout.buffer.write(encoding(export_release(args.job)))
            return 0
        require(args.directory is not None, 'select the private ceremony evidence directory')
        directory = state_dir(args.directory)
        if args.stage == 'begin':
            path = directory / 'plan.json'
            previous = json.loads(bounded_file(path), object_pairs_hook=relay.unique) if path.exists() else None
            binding = json.loads(bounded_file(args.binding), object_pairs_hook=relay.unique)
            site = json.loads(bounded_file(checked_file(args.site)), object_pairs_hook=relay.unique)
            plan = prepare_plan(binding, site, int(time.time()), previous)
            write_once(path, encoding(plan))
            print(path)
            return 0
        require(args.plan is not None, 'select the independently signed observation plan')
        signers = configured_signers()
        plan, plan_sha = verify_file(args.plan, observer_principal('plan'), signers)
        validate_plan(plan, int(time.time()))
        expected = probe_plan(plan)
        if args.stage == 'assemble':
            receipt = assembled_receipt(plan, plan_sha, directory, now=int(time.time()),
                                        verify=lambda path, principal: verify_file(path, principal, signers))
            path = directory / 'destination-receipt.json'
            if path.exists():
                old = json.loads(bounded_file(path), object_pairs_hook=relay.unique)
                require(old['expires_at'] > int(time.time())
                        and old == {**receipt, 'issued_at': old['issued_at'], 'expires_at': old['expires_at']},
                        'the existing receipt has expired or differs from this ceremony')
            else:
                write_once(path, encoding(receipt))
        elif args.stage == 'collect':
            path = observe(plan, plan_sha, args.test, args.family, directory, expected)
        else:
            transcript = bounded_file(args.transcript)
            require(args.observed_at <= int(time.time()), 'external observation time is in the future')
            if args.stage == 'record-access':
                record = external_probe(plan, plan_sha, args.test, args.family, expected, transcript, args.observed_at)
                path = directory / record_name(args.test, args.family)
            else:
                record = event_record(plan, plan_sha, args.event, args.before, args.after, transcript, args.observed_at)
                path = directory / record_name(args.event, 'event')
            write_once(path, encoding(record))
        print(path)
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, http.client.HTTPException) as exc:
        print('destination observation blocked: ' + str(exc), file=sys.stderr)
        return 1
    except ImportError:
        print('destination observation blocked: managed Chromium/Playwright runtime unavailable', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
