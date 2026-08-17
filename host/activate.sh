#!/usr/bin/env bash
# activate.sh — the bare-metal track's day zero, and root's only act there.
#
# WHAT MAKES THIS DIFFERENT FROM day-zero.sh. On the bare-metal track the image
# already carries every capability, and identity — `core`, its keys, its sudo
# hash — is baked from the trust root at build, because declarations are records
# (00-BYLAW.md). So this script INSTALLS NOTHING. A package installed here would
# be a mutable out-of-band change to an image-immutable host, which C7 forbids
# outright, and the host's OS state arrives by image rebase rather than from
# anything written here.
#
# What an image may never hold is the live credentials, and supplying those is
# the whole of the maintainer's one act: the tailnet join and the pair's GitHub
# App activation. Then root retires.
#
# WHAT IT DOES NOT CONTAIN. No credential, no key, no hash. `dev-pair` is a
# public repository, and live credentials rest only in the estate vault (C6;
# ADR 000011). Everything secret arrives at run time, after the single
# authorization below — the same shape day zero uses on the VPS track, because
# it is the same law.
#
# HOW TO USE IT. On a freshly installed strix, as root or through sudo:
#
#   sudo bash activate.sh
#
# Never down a pipe into a shell: C4 forbids fetch-piped-to-shell estate-wide,
# and this is the most privileged execution in the host's life. Fetch it, look
# at what arrived, then run it.
#
# It is safe to re-run. Every step reads live state first.
set -euo pipefail
export LC_ALL=C

REPO_URL=https://github.com/oso-gato/dev-pair
SRC=/var/lib/dev-pair/src
ENVIRONMENT="${CONVERGE_ENV:-strix}"

say()  { printf '\n\033[1m── %s ──\033[0m\n' "$*"; }
ok()   { printf '\033[32m[ok]\033[0m   %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "activation runs as root: sudo bash $0"

WORKDIR=$(mktemp -d); chmod 700 "$WORKDIR"
export GH_CONFIG_DIR="$WORKDIR/gh"
cleanup() {
    gh auth logout --hostname github.com >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — what the image already gave us, confirmed rather than created.
# ═════════════════════════════════════════════════════════════════════════════

say "phase 1: what the image already carries"

command -v gh        >/dev/null 2>&1 || die "gh is absent from this image — activation installs nothing, so the image must carry it"
command -v curl      >/dev/null 2>&1 || die "curl is absent from this image"
command -v tailscale >/dev/null 2>&1 || die "tailscale is absent from this image"
ok "gh, curl and tailscale present — nothing to install"

# The administrative user is baked, not created. Confirming it is the point:
# if the image did not bake it, this is not a host this script can activate.
id -u core >/dev/null 2>&1 || die "the image did not bake the administrative user — wrong image, or a build that lost it"
ADMIN_HOME_ACTUAL=$(getent passwd core | cut -d: -f6)
[ -s "$ADMIN_HOME_ACTUAL/.ssh/authorized_keys" ] \
    || die "core holds no authorized key — refusing to continue, because this run retires root"
ok "core is baked, in place, and holds $(wc -l < "$ADMIN_HOME_ACTUAL/.ssh/authorized_keys") key(s)"

# The declaration source. Public, so no authority is needed. git may not be on
# an image whose package set is minimal, so fall back to the codeload tarball —
# still a fetch of a public artifact, still no install.
install -d -m 0755 /var/lib/dev-pair
if command -v git >/dev/null 2>&1; then
    if [ -d "$SRC/.git" ]; then
        if git -C "$SRC" fetch --depth 1 origin main >/dev/null 2>&1 \
           && git -C "$SRC" reset --hard origin/main >/dev/null 2>&1; then
            ok "declaration source refreshed at $SRC"
        else
            warn "could not refresh $SRC; continuing with what is already there"
        fi
    else
        git clone --depth 1 "${REPO_URL}.git" "$SRC" >/dev/null 2>&1 || die "cannot clone ${REPO_URL}"
        ok "declaration source cloned to $SRC"
    fi
else
    curl -fsSL --proto '=https' --tlsv1.2 "${REPO_URL}/archive/refs/heads/main.tar.gz" \
        -o "$WORKDIR/src.tar.gz" || die "cannot fetch the declaration source"
    rm -rf "$SRC"; install -d -m 0755 "$SRC"
    tar -xzf "$WORKDIR/src.tar.gz" -C "$SRC" --strip-components=1 \
        || die "cannot unpack the declaration source"
    ok "declaration source fetched to $SRC (no git on this image; tarball used)"
fi

ENV_FILE="$SRC/host/converge/environments/${ENVIRONMENT}.env"
[ -f "$ENV_FILE" ] || die "no adapter for environment '${ENVIRONMENT}'"
# shellcheck source=converge/environments/strix.env
. "$ENV_FILE"
ok "environment adapter loaded (${PAIR_NAME}, ${PAIR_TRACK} track)"

# ═════════════════════════════════════════════════════════════════════════════
# THE ONE HUMAN ACT
# ═════════════════════════════════════════════════════════════════════════════

say "authorization — the one interaction this workflow asks for"

cat <<'EOF'
The rest of activation needs what an image may never hold: the tailnet auth key
and this pair's GitHub App private keys. They rest in the estate vault, and one
approval opens it.

A code is about to be printed. Approve it at github.com/login/device from your
phone or your laptop, signed in as the maintainer. Nothing else will be asked.
EOF

gh auth login --hostname github.com --git-protocol https --scopes repo --web \
    || die "authorization did not complete — nothing secret has been written, and re-running is safe"
ok "authorized"

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — the vault.
# ═════════════════════════════════════════════════════════════════════════════

say "phase 2: credentials from the vault"

vault_get() {
    local path="$1" dest="$2"
    gh api "repos/${VAULT_REPO}/contents/${path}" \
        -H "Accept: application/vnd.github.raw" > "$dest" 2>/dev/null || return 1
    [ -s "$dest" ] || return 1
}

# No password is set here. On this track the sudo hash is baked at image build
# from the trust root, so there is nothing to apply and nothing to read.
ok "no password to set — the sudo hash is baked at image build on this track"

# ── The tailnet ──────────────────────────────────────────────────────────────
# The auth key carries its expiry in its filename, so the newest unexpired key
# is chosen and an expired one is refused rather than presented.
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
    join_interactive=1
else
    vault_get "$TSKEY_PATH" "$WORKDIR/tskey" || die "cannot read the tailnet auth key from the vault"
    chmod 600 "$WORKDIR/tskey"
    ok "tailnet auth key retrieved ($(basename "$TSKEY_PATH"))"
    join_interactive=0
fi

# ── The pair's GitHub App identities ─────────────────────────────────────────
# These may not exist yet. The registry lists both strix Apps as planned, and
# creating a GitHub App is an act on github.com that no artifact can perform.
# An absent App is therefore a warned, non-fatal state: the host still joins and
# still runs its dev-container, and the boxes simply hold no GitHub authority
# until the maintainer creates the Apps and re-runs.
install -d -m 0755 "$PAIR_STATE_DIR"
install -d -m 0700 "$PAIR_SECRETS_DIR"
install -d -m 0700 -o core -g core "$PAIR_ADMIN_STATE"
install -d -m 0700 -o core -g core "$PAIR_DEV_SECRETS_DIR"

install_app() {
    local vault_key="$1" dir="$2" app_id="$3" inst_id="$4" owner="$5" label="$6"
    if [ -z "$app_id" ] || [ -z "$inst_id" ]; then
        warn "${label}: no App id in the adapter — this pair's Apps are not created yet, so ${label} will hold no GitHub authority"
        return 0
    fi
    install -d -m 0700 -o "${owner%%:*}" -g "${owner##*:}" "$dir"
    vault_get "$vault_key" "$dir/private-key.pem" \
        || { warn "${label}: no App key in the vault — no GitHub authority for it yet"; return 0; }
    # Validate by exit code alone: the key's contents never reach a terminal.
    openssl pkey -in "$dir/private-key.pem" -noout 2>/dev/null \
        || { rm -f "$dir/private-key.pem"; die "${label}'s App key is not a valid private key"; }
    printf '%s\n' "$app_id"  > "$dir/app-id"
    printf '%s\n' "$inst_id" > "$dir/installation-id"
    chmod 0600 "$dir"/*
    chown -R "$owner" "$dir"
    ok "${label} App identity installed (App ${app_id})"
}

install_app "$VAULT_HOST_APP_KEY" "$PAIR_SECRETS_DIR/github-app" \
    "$HOST_APP_ID" "$HOST_APP_INSTALLATION_ID" "root:root" "host"
install_app "$VAULT_DEV_APP_KEY" "$PAIR_DEV_SECRETS_DIR/${DEV_CONTAINER_NAME}-github-app" \
    "$DEV_APP_ID" "$DEV_APP_INSTALLATION_ID" "core:core" "$DEV_CONTAINER_NAME"

gh auth logout --hostname github.com >/dev/null 2>&1 || true
rm -rf "$GH_CONFIG_DIR"
ok "authorization token destroyed"

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3 — the pair's own state, the tailnet, and root's retirement.
# ═════════════════════════════════════════════════════════════════════════════

say "phase 3: the pair's own state"

# Only the units the image does not already carry — the adapter says which.
CONVERGE_ENV="$ENVIRONMENT" bash "$SRC/host/converge/converge.sh" --env "$ENVIRONMENT" \
    || die "converge failed — the host is partially activated, root is NOT retired, and re-running is safe"

say "tailnet"
if [ "$join_interactive" = 0 ]; then
    if tailscale up "${TAILSCALE_ARGS[@]}" --authkey="$(cat "$WORKDIR/tskey")"; then
        ok "joined the tailnet as ${TAILNET_HOSTNAME}, advertising the LAN route"
    else
        warn "the auth key was rejected — falling back to browser authentication"
        tailscale up "${TAILSCALE_ARGS[@]}" || warn "tailscale up did not complete; re-run: sudo tailscale up ${TAILSCALE_ARGS[*]}"
    fi
else
    tailscale up "${TAILSCALE_ARGS[@]}" || warn "tailscale up did not complete; re-run: sudo tailscale up ${TAILSCALE_ARGS[*]}"
fi
shred -u "$WORKDIR/tskey" 2>/dev/null || rm -f "$WORKDIR/tskey"

say "root retires"

# The donor image ships a bootstrap window of passwordless sudo so an operator
# can reach setup over key-authenticated SSH before a password exists. On this
# track the password is baked, so the window was never needed and closing it is
# unconditional. Named explicitly because it is a donor artifact, not ours.
for stale in /etc/sudoers.d/strix-bootstrap /etc/sudoers.d/90-cloud-init-users; do
    if [ -f "$stale" ]; then
        rm -f "$stale"
        ok "closed the bootstrap sudo window ($stale)"
    fi
done

# Recovery before power (C11): root is locked only once core is provably usable.
# Locking it first would strand a machine whose only other door is a key we have
# not confirmed works with a password we have not confirmed exists.
admin_ready=1
id -nG core 2>/dev/null | tr ' ' '\n' | grep -qx wheel || admin_ready=0
[ -s "$ADMIN_HOME_ACTUAL/.ssh/authorized_keys" ] || admin_ready=0
passwd -S core 2>/dev/null | awk '{print $2}' | grep -qx 'P' || admin_ready=0

if [ "$admin_ready" = 0 ]; then
    warn "root NOT retired — core is not provably usable (needs wheel, an authorized key, and the baked password). Fix the image, then re-run."
elif passwd -S root 2>/dev/null | awk '{print $2}' | grep -qE '^(L|LK)$'; then
    ok "root already retired"
else
    passwd -l root >/dev/null 2>&1 || die "cannot lock the root password"
    ok "root retired — core verified usable first"
fi

say "done"
cat <<EOF
${PAIR_NAME} is activated and ${DEV_CONTAINER_NAME} is running.

Reach it as core, by key, over the tailnet or the LAN:
    ssh core@${TAILNET_HOSTNAME}

Then:
    claude          a session in the host's agent box
    ${DEV_CONTAINER_NAME}           a session in the dev-container, resumable after any drop
    sudo ${SRC}/host/converge/converge.sh --env ${ENVIRONMENT}    re-apply the pair's state

The host's OS state is the image's and changes only by rebase. Nothing this
script did installed a package, and nothing it wrote lives outside the pair's
own directories.
EOF
