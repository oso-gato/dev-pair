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
    # Tolerant here and fatal on the VPS track, and the difference is a fact
    # rather than an accident: this pair's Apps are not created yet, so a
    # missing key is the expected state until the maintainer creates them.
    # Validated before it lands either way, so a failed fetch never replaces a
    # working key.
    vault_get "$vault_key" "$dir/private-key.pem" vault_is_pem \
        || { warn "${label}: no usable App key in the vault — no GitHub authority for it yet (${vault_why})"; return 0; }
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
