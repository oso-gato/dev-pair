#!/bin/sh
# claudebox-agent-repo — admit Anthropic's repository, then install the agent.
#
# Runs INSIDE the box, as root, piped in by claudebox-init.sh over the
# quote-safe `distrobox enter -- sudo` channel. It is a file rather than a
# distrobox.ini hook because `distrobox assemble` double-evaluates hooks, and
# everything below needs redirection, comparison and its own quoting. The
# manifest's own rule already said so; this is that rule applied to the one
# piece of work that had been left in a hook.
#
# What changed and why it matters: the hook wrote a repository definition whose
# gpgkey was a REMOTE URL. Under `dnf -y` that auto-imports whatever key the
# URL serves at the moment the box is assembled, so the fingerprint recorded in
# the manifest was a comment and nothing more — a decoration a reader would
# reasonably mistake for a control. Here the key is fetched, checked against
# that fingerprint before anything is imported, and the definition points at
# the local file that passed. A substituted key now stops the box build.
#
# What this still does NOT do: admit the vendor's own .repo file pinned by
# checksum, which is the stronger form the converger uses for Tailscale
# (prov_l2_vendor_repo). Anthropic publishes no such file that a session has
# been able to reach, so the definition below is this repository's own
# transcription and a substituted baseurl would not be detected. That residue
# is real, it is disclosed here and in docs/decisions/000032, and it is the
# first thing to close when a session can reach the vendor (C5).
set -eu

FPR=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
KEY_URL=https://downloads.claude.ai/keys/claude-code.asc
BASE_URL=https://downloads.claude.ai/claude-code/rpm/latest
KEYRING=/etc/pki/rpm-gpg/RPM-GPG-KEY-claude-code
REPOFILE=/etc/yum.repos.d/claude-code.repo

# The verifier has to exist before it can verify. L1, from Fedora's own
# repositories, so there is no unverified step ahead of it.
command -v gpg >/dev/null 2>&1 \
    || dnf -y --setopt=install_weak_deps=False install gnupg2 \
    || { echo "claudebox-agent-repo: cannot install the signature verifier" >&2; exit 1; }

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$KEY_URL" -o "$tmp" \
    || { echo "claudebox-agent-repo: signing key unreachable at $KEY_URL — nothing installed" >&2; exit 1; }
[ -s "$tmp" ] \
    || { echo "claudebox-agent-repo: signing key empty — nothing installed" >&2; exit 1; }

got=$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')
[ -n "$got" ] \
    || { echo "claudebox-agent-repo: signing key unreadable — nothing installed" >&2; exit 1; }
if [ "$got" != "$FPR" ]; then
    echo "claudebox-agent-repo: the key at $KEY_URL has fingerprint $got, not the pinned $FPR." >&2
    echo "Nothing installed. Re-verify upstream and re-pin deliberately (C5) — never relax this." >&2
    exit 1
fi

install -D -m 0644 "$tmp" "$KEYRING"
rpm --import "$KEYRING" \
    || { echo "claudebox-agent-repo: rpm refused the signing key — nothing installed" >&2; exit 1; }

# gpgkey is the LOCAL file that passed the check above, never the remote URL.
printf '[claude-code]\nname=Claude Code\nbaseurl=%s\nenabled=1\ntype=rpm\ngpgcheck=1\ngpgkey=file://%s\n' \
    "$BASE_URL" "$KEYRING" > "$REPOFILE"
chmod 0644 "$REPOFILE"

# Channel `latest` is deliberate and is what the DAILY rebuild is for: the box
# carries the current agent because it is rebuilt, never because it updated
# itself. Self-update stays disabled in managed-settings.json — a self-installed
# binary would shadow the managed one, survive the rebuild, and strand the layer
# stale while appearing current (C8).
dnf -y --setopt=install_weak_deps=False install claude-code \
    || { echo "claudebox-agent-repo: claude-code did not install" >&2; exit 1; }

echo "claudebox-agent-repo: key pinned to $FPR, claude-code installed."
