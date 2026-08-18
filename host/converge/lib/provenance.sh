#!/usr/bin/env bash
# provenance.sh — the one pinned-fetch contract (C4).
#
# C4 asks for one fetch mechanism per system, at one strength: "a definition
# fetched unverified on the most privileged component while pinned on another
# is the canonical violation." Day zero and every converger unit therefore
# admit artifacts through these functions and through nothing else.
#
# The ladder, as this repository instantiates it (00-BYLAW.md):
#   L1  Fedora's own dnf repositories.
#   L2  the vendor's OWN dnf .repo file, fetched and pinned by checksum. Not
#       a definition we compose against the vendor's baseurl: the point is
#       that the vendor's file is the thing verified.
#   L3  an official-upstream binary, graded and disclosed. Nothing on erebus
#       needs L3, and prov_l3_fetch exists so that if something ever does, it
#       cannot be admitted without a checksum.
#
# Admission is enforced at the fetch: on a mismatch or an absent signature
# nothing installs and the run stops. Every admitted artifact is disclosed to
# ${PAIR_STATE_DIR}/provenance.tsv, which is the host's own record of what it
# is made of.
#
# Sourced, never executed. Requires log.sh.

# prov_sha256 — the bare sha256 of a file.
#
# Deliberately `cut` rather than an awk program. The awk form carried nested
# quoting that survived `bash -n` and shellcheck while silently yielding
# "<hash>  <path>" instead of the hash, so every checksum comparison failed and
# every admission died closed on a correct file. One home, no quoting hazard,
# and exercised directly by the self-test.
prov_sha256() {
    sha256sum "$1" | cut -d' ' -f1
}

PROV_DISCLOSURE="${PAIR_STATE_DIR:-/var/lib/dev-pair}/provenance.tsv"

# ── Disclosure ───────────────────────────────────────────────────────────────
# Every admitted artifact carries its disclosure (C4). Rewriting an existing
# row rather than appending keeps the record a current-state fact list, so a
# re-run does not grow it — which is what lets acceptance 3 read zero changes.
prov_disclose() {
    local artifact="$1" level="$2" source="$3" note="${4:-}"
    local dir; dir=$(dirname "$PROV_DISCLOSURE")
    install -d -m 0755 "$dir"
    [ -f "$PROV_DISCLOSURE" ] || {
        printf 'artifact\tlevel\tsource\tadmitted\tnote\n' > "$PROV_DISCLOSURE"
        chmod 0644 "$PROV_DISCLOSURE"
    }
    local today; today=$(date -u +%Y-%m-%d)
    local tmp; tmp=$(mktemp)
    awk -F'\t' -v a="$artifact" 'NR==1 || $1 != a' "$PROV_DISCLOSURE" > "$tmp"
    printf '%s\t%s\t%s\t%s\t%s\n' "$artifact" "$level" "$source" "$today" "$note" >> "$tmp"
    mv -f "$tmp" "$PROV_DISCLOSURE"
    chmod 0644 "$PROV_DISCLOSURE"
}

# ── Bootstrap ────────────────────────────────────────────────────────────────
# The contract needs a fetcher and a verifier before it can verify anything.
# Both come from Fedora's own repositories, so this is L1 all the way down and
# there is no unverified step ahead of the verifier.
prov_bootstrap() {
    local need=()
    command -v curl >/dev/null 2>&1 || need+=(curl)
    command -v gpg  >/dev/null 2>&1 || need+=(gnupg2)
    if [ ${#need[@]} -gt 0 ]; then
        dnf -y --setopt=install_weak_deps=False install "${need[@]}" \
            || log_die "cannot install the fetch contract's own tools (${need[*]}) from Fedora's repositories"
        log_changed "provenance: installed fetch tooling (${need[*]}, L1)"
    fi
    prov_disclose "curl" "L1" "fedora" "fetch contract"
    prov_disclose "gnupg2" "L1" "fedora" "fetch contract, signature verification"
}

# ── L1 ───────────────────────────────────────────────────────────────────────
# Fedora's own repositories. install_weak_deps=False on every installation,
# bootstrap paths included (00-BYLAW.md, minimalism flag).
#
# Idempotent by reading live state: already-present packages are never passed
# to dnf, so a converged host performs no transaction and reports no change.
prov_l1_install() {
    local why="$1"; shift
    [ $# -gt 0 ] || return 0
    local missing=() p
    for p in "$@"; do
        rpm -q --whatprovides "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if [ ${#missing[@]} -eq 0 ]; then
        log_ok "packages present (${*})"
    else
        dnf -y --setopt=install_weak_deps=False install "${missing[@]}" \
            || log_die "L1 install failed: ${missing[*]}"
        log_changed "installed ${missing[*]} — $why"
    fi
    for p in "$@"; do prov_disclose "$p" "L1" "fedora" "$why"; done
}

# ── L2 ───────────────────────────────────────────────────────────────────────
# A vendor's own dnf repository, and only ever the vendor's own definition of
# it. There is one function for this and it is prov_l2_vendor_repo below.
#
# This section used to carry a second function, prov_l2_repo, which composed a
# repository definition from arguments — an id, a name, a baseurl, a key URL —
# and wrote our transcription of the vendor's file rather than the file. That
# is the weaker mechanism, and C4 asks for one fetch mechanism per system at
# one strength precisely so the weaker one is not available to reach for. It
# was also unreachable in practice: nothing on either lineage ever called it.
# A transcription cannot detect a substituted baseurl or a moved gpgkey URL,
# because the transcription is the thing being compared against. So it is
# gone, and its absence is what the self-test guards.
#
# When a vendor publishes no .repo file of its own, that is a new case to be
# graded against a real vendor at the time it arrives, not scaffolding kept
# warm against a need nobody has yet had.

# prov_l2_vendor_repo — admit the vendor's OWN .repo file, pinned by checksum.
#
# Stronger than authoring our own definition against the vendor's baseurl, and
# adopted from the estate's own measured practice (docs/decisions/000031). Two
# things it buys: the definition is the vendor's rather than our transcription
# of it, and a changed upstream file stops the run instead of silently
# redefining where packages come from — a swapped baseurl or gpgkey URL is
# exactly the substitution a hand-written .repo cannot detect.
#
# Fail-closed on every path, cache hits included: on a checksum mismatch
# nothing is written and nothing installs. Re-pin deliberately, after a live
# re-check (C5), never by relaxing the comparison.
#
#   prov_l2_vendor_repo <id> <repo-file-url> <sha256>
prov_l2_vendor_repo() {
    local id="$1" url="$2" want="$3"
    local repofile="/etc/yum.repos.d/${id}.repo"

    local tmp; tmp=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$url" -o "$tmp" \
        || log_die "L2 ${id}: vendor repository definition unreachable at ${url} — nothing installed"

    local got; got=$(prov_sha256 "$tmp")
    [ "$got" = "$want" ] \
        || log_die "L2 ${id}: the vendor definition at ${url} has sha256 ${got}, not the pinned ${want}. Nothing installed. Re-verify upstream and re-pin deliberately (C5) — never relax this comparison."

    if [ -f "$repofile" ] && cmp -s "$tmp" "$repofile"; then
        log_ok "L2 ${id}: vendor repository definition current (sha256 pinned)"
    else
        install -m 0644 "$tmp" "$repofile"
        log_changed "L2 ${id}: vendor repository definition admitted (sha256 ${want})"
    fi
    prov_disclose "repo:${id}" "L2" "$url" "vendor definition, sha256-pinned ${want}"
}

# prov_l2_install — install from a repository admitted by prov_l2_vendor_repo.
prov_l2_install() {
    local repoid="$1" why="$2"; shift 2
    local missing=() p
    for p in "$@"; do
        rpm -q --whatprovides "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if [ ${#missing[@]} -eq 0 ]; then
        log_ok "packages present (${*})"
    else
        dnf -y --setopt=install_weak_deps=False install "${missing[@]}" \
            || log_die "L2 install from ${repoid} failed: ${missing[*]}"
        log_changed "installed ${missing[*]} from ${repoid} — $why"
    fi
    for p in "$@"; do prov_disclose "$p" "L2" "$repoid" "$why"; done
}

# ── L3 ───────────────────────────────────────────────────────────────────────
# Last resort, admitted only where no L1 or L2 source exists, and never without
# a checksum to verify against. Nothing on erebus uses this today; it exists so
# that the first thing that needs it cannot be admitted ungraded.
prov_l3_fetch() {
    local url="$1" dest="$2" sha256="$3" why="$4"
    [ -n "$sha256" ] || log_die "L3 ${url}: refused — an L3 artifact without a checksum is not admissible (C4)"
    local tmp; tmp=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$tmp'" RETURN
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$url" -o "$tmp" \
        || log_die "L3 ${url}: unreachable — nothing installed"
    local got; got=$(prov_sha256 "$tmp")
    [ "$got" = "$sha256" ] \
        || log_die "L3 ${url}: sha256 ${got} does not match the pinned ${sha256} — nothing installed"
    install -D -m 0755 "$tmp" "$dest"
    log_changed "L3 ${url} admitted to ${dest} (c2, checksum-verified)"
    prov_disclose "$(basename "$dest")" "L3-c2" "$url" "$why; sha256 ${sha256}"
}
