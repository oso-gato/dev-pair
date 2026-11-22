"""Model installed root ancestry, keeping owned fixture metadata real."""
import os
from pathlib import Path
import stat


def root_observation(base, lstat):
    # The checkout/home/platform namespace is not the product's installed
    # artifact namespace. Only these exact pre-observed external directory
    # identities receive its trusted-root/traversal boundary. No chmod occurs.
    external=set()
    for path in Path(base).parents:
        info=lstat(path)
        if not stat.S_ISDIR(info.st_mode):raise AssertionError('external fixture ancestor is not a directory')
        external.add((info.st_dev,info.st_ino))
    def observe(info):
        fields=list(info);fields[4]=0  # Existing explicit root-ownership fixture.
        if (info.st_dev,info.st_ino) in external:
            if not stat.S_ISDIR(info.st_mode):raise AssertionError('external directory identity changed type')
            fields[0]=stat.S_IFMT(info.st_mode)|0o755
        return os.stat_result(fields)
    return observe
