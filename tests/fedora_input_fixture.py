"""External Fedora trust boundary injection for unrelated synthetic engine tests only."""
import contextlib
import hashlib
from pathlib import Path
from unittest.mock import patch
import fedora_oci

@contextlib.contextmanager
def synthetic_verified(source, **kwargs):
    root = Path(source); root.mkdir(exist_ok=True)
    for name in fedora_oci.FILES:
        if not (root / name).exists(): (root / name).write_bytes(b'UNTRUSTED SYNTHETIC INPUT, NOT FEDORA')
    yield root / 'fixture.oci.tar', {'fixture': 'not signature evidence'}


def synthetic_import(engine, plain, uid=None, seconds=120):
    engine('load', '--input', str(plain))
    engine('save', '--format=oci-archive', '--output', str(plain.parent / 'fixture-export'), fedora_oci.IMAGE)
    return {'source': dict(fedora_oci.PROVENANCE), 'fixture': 'NOT a native import verdict'}


def install(test):
    fake = b'UNTRUSTED SYNTHETIC INPUT, NOT FEDORA'
    artifacts = {name:(url,len(fake),hashlib.sha256(fake).hexdigest()) for name,(url,_,_) in fedora_oci.ARTIFACTS.items()}
    for item in (patch.object(fedora_oci, 'copy_workspace', synthetic_copy),
                 patch.object(fedora_oci, 'ARTIFACTS', artifacts),
                 patch.object(fedora_oci, 'verified', synthetic_verified),
                 patch.object(fedora_oci, 'import_image', synthetic_import)):
        item.start(); test.addCleanup(item.stop)


@contextlib.contextmanager
def synthetic_copy(parent, **kwargs):
    root=Path(parent)/'image-copy';root.mkdir(exist_ok=True)
    try:yield root
    finally:root.rmdir()
