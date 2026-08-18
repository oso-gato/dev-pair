#!/usr/bin/env bash
# day-zero.sh — the one pasted script, and root's only act, ever.
#
# WHERE THIS RUNS. Hostinger's own web console gives a root shell on the stock
# Fedora Cloud 44 template. A provider's out-of-band console is not remote
# authentication (C7), so that shell is where day zero legitimately begins —
# and it closes here, when this script creates `core` and retires root.
#
# WHAT IT DOES NOT CONTAIN. No credential, no key, no hash. `dev-pair` is a
# public repository, and identity declarations have their one home in the
# estate vault (C6). Everything secret arrives at run time, from outside this
# artifact, after the single authorization below.
#
# THE ONE HUMAN ACT. The workflow counts exactly one interaction, so this
# script asks exactly once: a GitHub device-flow approval, roughly in the
# middle. Before it, everything is public and needs no authority. After it, the
# vault opens and the run completes on its own. There is no second prompt.
#
# HOW TO USE IT. Paste this file's contents into the console's root shell, which
# is what the bylaw's day-zero contract describes — one pasted script.
#
# Fetching it instead is fine, but never down a pipe into a shell. C4 forbids
# fetch-piped-to-shell estate-wide, and this is the most privileged execution
# on the host's whole life, so it is the last place to make an exception. Fetch,
# look at what arrived, then run it:
#
#   curl -fsSLo day-zero.sh https://raw.githubusercontent.com/oso-gato/dev-pair/main/host/day-zero.sh
#   sha256sum day-zero.sh          # compare against the commit you mean to run
#   bash day-zero.sh
#
# It is safe to re-run. Every step reads live state first, and the converger it
# hands off to is idempotent by construction.
set -euo pipefail
export LC_ALL=C

REPO_URL=https://github.com/oso-gato/dev-pair.git
SRC=/var/lib/dev-pair/src
ENVIRONMENT="${CONVERGE_ENV:-erebus}"

say()  { printf '\n\033[1m── %s ──\033[0m\n' "$*"; }
ok()   { printf '\033[32m[ok]\033[0m   %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "day zero runs as root, in the provider's console."

# Everything the device flow touches lives here and is destroyed on exit, so a
# power loss mid-run strands no token on disk.
WORKDIR=$(mktemp -d); chmod 700 "$WORKDIR"
export GH_CONFIG_DIR="$WORKDIR/gh"
cleanup() {
    gh auth logout --hostname github.com >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — public only. Nothing here needs authority of any kind.
# ═════════════════════════════════════════════════════════════════════════════

say "phase 1: the host, from public sources only"

# L1 throughout, with weak dependencies off from the very first transaction —
# C4's minimal installation rule binds bootstrap paths too, which is exactly the
# path most likely to be exempted by habit.
dnf -y --setopt=install_weak_deps=False install git gh curl gnupg2 python3 \
    || die "cannot install the bootstrap set from Fedora's own repositories"
ok "bootstrap set installed (git, gh, curl, gnupg2, python3 — all L1)"

# The declaration source. Public, so no authority is needed to read it, and the
# converger re-runs from here for the life of the host.
install -d -m 0755 /var/lib/dev-pair
if [ -d "$SRC/.git" ]; then
    if git -C "$SRC" fetch --depth 1 origin main >/dev/null 2>&1 \
       && git -C "$SRC" reset --hard origin/main >/dev/null 2>&1; then
        ok "declaration source refreshed at $SRC"
    else
        warn "could not refresh $SRC; continuing with what is already there"
    fi
else
    git clone --depth 1 "$REPO_URL" "$SRC" >/dev/null 2>&1 \
        || die "cannot clone $REPO_URL"
    ok "declaration source cloned to $SRC"
fi

ENV_FILE="$SRC/host/converge/environments/${ENVIRONMENT}.env"
[ -f "$ENV_FILE" ] || die "no adapter for environment '${ENVIRONMENT}'"
# shellcheck source=converge/environments/erebus.env
. "$ENV_FILE"
ok "environment adapter loaded (${PAIR_NAME}, ${PAIR_TRACK} track)"

# The administrative user, created before anything is authorised, so the
# machine has an owner other than root at the earliest possible moment.
if id -u "$ADMIN_USER" >/dev/null 2>&1; then
    ok "user ${ADMIN_USER} already exists"
else
    useradd --create-home --shell /bin/bash --groups wheel "$ADMIN_USER"
    ok "created ${ADMIN_USER}"
fi

# The trust root is public, so the keys land now rather than after the
# authorization — which means a locked-out operator can already get back in by
# SSH before this script has finished.
install -D -m 0755 "$SRC/shared/bin/pair-keys-sync" "$BIN_DIR/pair-keys-sync"
runuser -u "$ADMIN_USER" -- env "TRUST_ROOT_USER=$TRUST_ROOT_USER" "$BIN_DIR/pair-keys-sync" \
    || die "cannot authorize the maintainer's keys from the trust root"

AK="$(getent passwd "$ADMIN_USER" | cut -d: -f6)/.ssh/authorized_keys"
[ -s "$AK" ] || die "no key was authorized for ${ADMIN_USER} — refusing to continue, because the next phase closes the console path"
ok "authorized $(wc -l < "$AK") key(s) for ${ADMIN_USER} from github.com/${TRUST_ROOT_USER}.keys"

# Keys-only SSH, applied now rather than at the end. Password authentication is
# open on the stock template, and leaving it open for the length of this run
# would be a window nobody declared.
install -D -m 0644 "$SRC/host/sysroot/etc/ssh/sshd_config.d/40-dev-pair.conf" \
    /etc/ssh/sshd_config.d/40-dev-pair.conf
sshd -t || die "the keys-only sshd configuration does not parse — nothing reloaded"
systemctl reload sshd 2>/dev/null || systemctl restart sshd || die "cannot reload sshd"
ok "sshd is keys-only; root cannot authenticate remotely"

# ═════════════════════════════════════════════════════════════════════════════
# THE ONE HUMAN ACT
# ═════════════════════════════════════════════════════════════════════════════

say "authorization — the one interaction this workflow asks for"

cat <<'EOF'
The rest of day zero needs three things a public artifact may never hold: the
administrative user's password hash, the tailnet auth key, and this pair's
GitHub App private keys. They rest in the estate vault, and one approval opens
it.

A code is about to be printed. Approve it at github.com/login/device from your
phone or your laptop, signed in as the maintainer. Nothing else will be asked.
EOF

# stdin is closed here, deliberately, and it is load-bearing. This script's
# contract is one pasted block (see the header), and a command that reads stdin
# from inside a paste consumes the NEXT pasted lines as its answer — bash never
# executes them. gh asks twice when it believes it has a terminal: a
# git-credential question, and "press Enter to open your browser". With stdin
# closed it prints the URL and the one-time code and waits for the approval
# rather than for a keystroke. --git-protocol is gone for the same reason: it
# is what arms the first of those two prompts, and nothing here moves git over
# the token, so it bought nothing and cost a prompt.
gh auth login --hostname github.com --scopes repo --web </dev/null \
    || die "authorization did not complete — nothing secret has been written, and re-running day zero is safe"

# Who approved it, and can they actually open the vault? Without this an
# operator signed in as the wrong account passes straight through, every vault
# fetch fails one at a time, and the run ends on a host that looks finished and
# holds no identity. Ask once, here, while saying so is still cheap.
GH_LOGIN=$(gh api user --jq .login 2>/dev/null) \
    || die "authorization produced no usable token — re-run day zero"
[ "$GH_LOGIN" = "$TRUST_ROOT_USER" ] \
    || die "authorized as ${GH_LOGIN}, but this estate's trust root is ${TRUST_ROOT_USER}. Sign in as the maintainer and re-run."
gh api "repos/${VAULT_REPO}" >/dev/null 2>&1 \
    || die "authorized as ${GH_LOGIN}, which cannot read ${VAULT_REPO}. The vault is private and this account has no access to it."
ok "authorized as ${GH_LOGIN}; the vault is readable"

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — the vault. Everything below is a credential and none of it is
# printed, logged, or written anywhere but its final destination.
# ═════════════════════════════════════════════════════════════════════════════

say "phase 2: identity from the vault"

vault_get() {
    # Fetch a vault file's raw bytes to a destination path, never to stdout.
    #
    # Staged INSIDE the destination directory and renamed into place. Never
    # written onto the destination, and never staged in $WORKDIR. Both rules
    # were learned rather than reasoned. A redirection onto the destination
    # truncates the incumbent before the fetch has run, so a network blip on a
    # re-run destroyed a working App key and left a zero-byte file that later
    # units reported as present. And a rename across filesystems carries the
    # source's SELinux label, which is why the estate's key sync renames within
    # ~/.ssh rather than in from /tmp.
    #
    # The optional validator is handed the staged file and decides whether it
    # may land. Exit status alone does not decide it: gh writes error bodies to
    # stdout, so a 404 page arrives non-empty, and a path that resolves to a
    # directory arrives as a JSON array with status 0.
    #
    # On any failure the incumbent is untouched and vault_why carries the
    # reason, so a caller can say what went wrong instead of guessing.
    local path="$1" dest="$2" validate="${3:-}"
    local tmp="${dest}.new" err rc=0
    vault_why=""

    install -m 0600 /dev/null "$tmp" 2>/dev/null \
        || { vault_why="cannot stage a file beside ${dest}"; return 1; }

    # stderr to the capture, stdout to the file — the order of the two
    # redirections is what separates them.
    err=$(gh api "repos/${VAULT_REPO}/contents/${path}" \
              -H "Accept: application/vnd.github.raw" 2>&1 >"$tmp") || rc=$?
    if [ "$rc" -ne 0 ]; then
        rm -f "$tmp"; vault_why="${err:-gh reported no reason}"; return 1
    fi
    if [ ! -s "$tmp" ]; then
        rm -f "$tmp"; vault_why="the vault returned an empty file"; return 1
    fi
    if [ -n "$validate" ] && ! "$validate" "$tmp"; then
        rm -f "$tmp"; vault_why="the bytes returned for ${path} are not what it should hold"; return 1
    fi
    mv -f "$tmp" "$dest" \
        || { rm -f "$tmp"; vault_why="cannot place the fetched file at ${dest}"; return 1; }
}

# Validators. The PEM one asserts positively, because openssl can prove it. The
# other only refuses what a failed fetch looks like — a JSON error body or a
# directory listing — rather than asserting a format no session has verified.
vault_is_pem() {
    grep -q -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$1" 2>/dev/null \
        && openssl pkey -in "$1" -noout 2>/dev/null
}

vault_not_json() {
    ! head -c 1 "$1" 2>/dev/null | grep -q '[{[]'
}

# ── The administrative password ──────────────────────────────────────────────
# A hash is a declaration rather than a secret (C6), but it is still not
# something a public repository may carry, so it comes from the vault like the
# rest. It gates sudo and nothing else: no password authenticates a remote
# shell anywhere in the platform.
vault_get "$VAULT_CORE_DECLARATION" "$WORKDIR/core-user.md" vault_not_json \
    || die "cannot read the core declaration from the vault — ${vault_why}"

CORE_HASH=$(python3 - "$WORKDIR/core-user.md" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'password hash, main:\s*`([^`]+)`', text)
print(m.group(1).strip() if m else "")
PY
)
[ -n "$CORE_HASH" ] || die "no main password hash found in the core declaration"
# shellcheck disable=SC2016  # a literal SHA-512 crypt prefix, not an expansion
case "$CORE_HASH" in
    '$6$'*) : ;;
    *) die "the core password hash is not the SHA-512 crypt the declaration promises" ;;
esac
usermod -p "$CORE_HASH" "$ADMIN_USER" || die "cannot apply the core password hash"
unset CORE_HASH
ok "administrative password applied — sudo now requires it"

# ── The tailnet ──────────────────────────────────────────────────────────────
# The auth key carries its expiry in its filename, which makes the expiry
# usable rather than decorative: pick the newest key that has not expired, and
# refuse rather than present an expired one to the tailnet.
# shellcheck disable=SC2016  # --jq runs server-side; $ must not expand here
TSKEY_PATH=$(gh api "repos/${VAULT_REPO}/contents/identity" --jq '.[].name' 2>/dev/null \
    | grep -E '^tskey-auth-.*-expiry\.key$' \
    | python3 -c '
import sys, datetime, re
today = datetime.date.today()
best = None
for name in (l.strip() for l in sys.stdin if l.strip()):
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", name)
    if not m: continue
    d = datetime.date(*map(int, m.groups()))
    if d >= today and (best is None or d > best[0]):
        best = (d, name)
print(f"identity/{best[1]}" if best else "")
') || TSKEY_PATH=""

if [ -z "$TSKEY_PATH" ]; then
    warn "no unexpired tailnet auth key in the vault — falling back to browser authentication"
    tailscale_join_interactive=1
else
    vault_get "$TSKEY_PATH" "$WORKDIR/tskey" vault_not_json \
        || die "cannot read the tailnet auth key from the vault — ${vault_why}"
    chmod 600 "$WORKDIR/tskey"
    ok "tailnet auth key retrieved ($(basename "$TSKEY_PATH"))"
    # The dev-container is its own tailnet node (docs/decisions/000030), so it
    # needs the key too. Written where its Quadlet mounts it read-only; the
    # container reads it once at join and its tailnet state persists after, so
    # the key is not needed again.
    install -d -m 0700 -o "$ADMIN_USER" -g "$ADMIN_USER" \
        "$PAIR_DEV_SECRETS_DIR/${DEV_CONTAINER_NAME}-tailscale"
    install -m 0600 -o "$ADMIN_USER" -g "$ADMIN_USER" "$WORKDIR/tskey" \
        "$PAIR_DEV_SECRETS_DIR/${DEV_CONTAINER_NAME}-tailscale/authkey"
    ok "tailnet auth key placed for ${DEV_CONTAINER_NAME}"
    tailscale_join_interactive=0
fi

# ── The pair's GitHub App identities ─────────────────────────────────────────
# One App per pair-component per agent, never shared (ADR 000012). The host's
# App carries no merge permission and the dev-container's does, which is the
# host-never-merges boundary enforced by GitHub rather than by our restraint.
install -d -m 0755 "$PAIR_STATE_DIR"
install -d -m 0700 "$PAIR_SECRETS_DIR"
install -d -m 0700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$PAIR_ADMIN_STATE"
install -d -m 0700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$PAIR_DEV_SECRETS_DIR"

install_app() {
    local vault_key="$1" dir="$2" app_id="$3" inst_id="$4" owner="$5" label="$6"
    install -d -m 0700 -o "${owner%%:*}" -g "${owner##*:}" "$dir"
    # Validated before it lands, so a failed or wrong fetch never replaces a
    # working key. The key's contents never reach a terminal — the validator
    # decides by exit code alone.
    vault_get "$vault_key" "$dir/private-key.pem" vault_is_pem \
        || die "cannot install ${label}'s App key — ${vault_why}"
    printf '%s\n' "$app_id"  > "$dir/app-id"
    printf '%s\n' "$inst_id" > "$dir/installation-id"
    chmod 0600 "$dir"/*
    chown -R "$owner" "$dir"
    ok "${label} App identity installed (App ${app_id})"
}

# Fatal on this track, deliberately, and unlike the bare-metal one. Both of
# erebus's Apps exist and are declared in the adapter, so a failed fetch means
# something is actually wrong — the wrong account authorized, a moved vault
# path, a network fault — and continuing would hand back a host that looks
# converged and holds no GitHub identity. Day zero is re-runnable, so stopping
# here costs a re-run and buys the end of green-while-broken.
install_app "$VAULT_HOST_APP_KEY" "$PAIR_SECRETS_DIR/github-app" \
    "$HOST_APP_ID" "$HOST_APP_INSTALLATION_ID" "root:root" "host"
install_app "$VAULT_DEV_APP_KEY" "$PAIR_DEV_SECRETS_DIR/${DEV_CONTAINER_NAME}-github-app" \
    "$DEV_APP_ID" "$DEV_APP_INSTALLATION_ID" "${ADMIN_USER}:${ADMIN_USER}" "$DEV_CONTAINER_NAME"

# The authorization has done its whole job. Destroy the token now rather than
# at exit, so it does not outlive its purpose by the length of a converge run.
gh auth logout --hostname github.com >/dev/null 2>&1 || true
rm -rf "$GH_CONFIG_DIR"
ok "authorization token destroyed"

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3 — hand off to the converger, then retire root.
# ═════════════════════════════════════════════════════════════════════════════

say "phase 3: converge"

CONVERGE_ENV="$ENVIRONMENT" bash "$SRC/host/converge/converge.sh" --env "$ENVIRONMENT" \
    || die "converge failed — the host is partially configured, root is NOT retired, and re-running day zero is safe"

# The tailnet join needs the key, so it happens here rather than in a converger
# unit: a converge run holds no credentials and must never need any.
say "tailnet"
if [ "$tailscale_join_interactive" = 0 ]; then
    if tailscale up "${TAILSCALE_ARGS[@]}" --authkey="$(cat "$WORKDIR/tskey")"; then
        ok "joined the tailnet as ${TAILNET_HOSTNAME}"
    else
        warn "the auth key was rejected — falling back to browser authentication"
        tailscale up "${TAILSCALE_ARGS[@]}" || warn "tailscale up did not complete; re-run: sudo tailscale up ${TAILSCALE_ARGS[*]}"
    fi
else
    tailscale up "${TAILSCALE_ARGS[@]}" || warn "tailscale up did not complete; re-run: sudo tailscale up ${TAILSCALE_ARGS[*]}"
fi
shred -u "$WORKDIR/tskey" 2>/dev/null || rm -f "$WORKDIR/tskey"

say "done"
cat <<EOF
${PAIR_NAME} is converged and ${DEV_CONTAINER_NAME} is running.

Reach it as ${ADMIN_USER}, by key, over the tailnet:
    ssh ${ADMIN_USER}@${TAILNET_HOSTNAME}

Then:
    claude          a session in the host's agent box
    ${DEV_CONTAINER_NAME}             a session in the dev-container, resumable after any drop
    sudo /var/lib/dev-pair/src/host/converge/converge.sh    re-converge

Root is retired. This console will not authenticate it again, and no password
authenticates a remote shell anywhere on this host.
EOF
