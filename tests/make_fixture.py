"""Generate explicit offline fixtures. Never use these identities on a real target."""
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(exist_ok=False)
binary = b'OFFLINE TEST FIXTURE: this is not Codex\n'
(root / 'codex.fixture').write_bytes(binary)
manifest = {
    'kind': 'fixture',
    'source_sha': '33e08e550690d6954009c3f84bbfd2bec5a6c571',
    'standards_sha': '08fc080dc8463a16e7ef753eefdefd98463b76b9',
    'fedora': {'image': 'registry.fedoraproject.org/fedora:45@sha256:' + '0' * 64,
               'verification': 'FIXTURE ONLY: no upstream verification'},
    'codex': {'version': '0.0.0',
              'source': 'https://github.com/openai/codex/releases/download/rust-v0.0.0/codex-x86_64-unknown-linux-musl.tar.gz',
              'sha256': hashlib.sha256(binary).hexdigest(),
              'verification': 'FIXTURE ONLY: hash of fixture bytes, not official Codex'},
    'role': 'development', 'provider': 'gptbox', 'model': 'gpt-6.1-sol', 'effort': 'high',
    'mounts': {name: '/var/lib/dev-pair/jobs/fixture/' + name
               for name in ('workspace', 'state', 'cache', 'credentials')},
}
(root / 'inputs.fixture.json').write_text(json.dumps(manifest, indent=2) + '\n')
