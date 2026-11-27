#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export GIT_OPTIONAL_LOCKS=0
case "${1:-}" in
    start|resume) interactive=1 ;;
    status|access-request|access-response|access-probe) interactive=0 ;;
    *) printf 'Usage: ./day0.sh {start|status|resume|access-request|access-response|access-probe} [options]\n' >&2; exit 2 ;;
esac
if (( EUID != 0 )); then
    printf 'Open the selected VPS root terminal in hPanel, then run this command there.\n' >&2
    exit 2
fi
if [[ ! -x /usr/bin/python3 ]]; then
    printf 'The selected Fedora host needs its stock Python 3 before this verified kit can run.\n' >&2
    exit 2
fi
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if (( interactive )) && ! { : </dev/tty; } 2>/dev/null && [[ -t 0 && -x /usr/bin/script ]]; then
    printf -v command '%q ' /usr/bin/python3 -EBs "$repo/tools/owner_day0.py" "$@"
    exec /usr/bin/script -q -e -c "$command" /dev/null
fi
exec /usr/bin/python3 -EBs "$repo/tools/owner_day0.py" "$@"
