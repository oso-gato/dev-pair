#!/usr/bin/env bash
# fs.sh — idempotent filesystem and systemd operations.
#
# Idempotence here is a property of each operation, never a sentinel guarding
# it. Every function reads the live state, compares it against the declaration,
# and acts only on the difference — so a converged host performs no work
# because there is no difference, not because a marker said to skip. That is
# what makes a second apply's silence mean something (acceptance 3).
#
# Sourced, never executed. Requires log.sh.

# fs_install <src> <dest> <mode> [owner:group]
# Install a declared file, but only when its content or metadata differs.
fs_install() {
    local src="$1" dest="$2" mode="$3" owner="${4:-root:root}"
    [ -f "$src" ] || log_die "declared file missing from the repository: $src"

    local changed=0
    if [ ! -f "$dest" ] || ! cmp -s "$src" "$dest"; then
        install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$dest" \
            || log_die "cannot install $dest"
        changed=1
    else
        local cur_mode cur_owner
        cur_mode=$(stat -c '%a' "$dest")
        cur_owner=$(stat -c '%U:%G' "$dest")
        if [ "$cur_mode" != "${mode#0}" ] && [ "0$cur_mode" != "$mode" ]; then
            chmod "$mode" "$dest"; changed=1
        fi
        if [ "$cur_owner" != "$owner" ]; then
            chown "$owner" "$dest"; changed=1
        fi
    fi

    if [ "$changed" = 1 ]; then
        log_changed "installed $dest"
    else
        log_ok "$dest current"
    fi
}

# fs_render <template> <dest> <mode> <VAR>...
# Install a declared template with @@VAR@@ placeholders replaced by the named
# adapter variables. Rendering happens before the comparison, so a template
# whose substituted output is unchanged is still a no-op — which is what keeps
# a per-pair definition from making every converge run report a change.
#
# An unset variable is fatal rather than substituted empty: a Quadlet with a
# blank image name would start nothing and say nothing.
fs_render() {
    local tpl="$1" dest="$2" mode="$3"; shift 3
    [ -f "$tpl" ] || log_die "declared template missing from the repository: $tpl"
    local rendered; rendered=$(cat "$tpl")
    local v
    for v in "$@"; do
        [ -n "${!v:-}" ] || log_die "cannot render $(basename "$tpl"): the adapter does not set $v"
        rendered=${rendered//@@${v}@@/${!v}}
    done
    case "$rendered" in
        *@@*) log_die "cannot render $(basename "$tpl"): an @@placeholder@@ was left unsubstituted" ;;
    esac

    if [ -f "$dest" ] && [ "$(cat "$dest")" = "$rendered" ]; then
        log_ok "$dest current"
    else
        install -d -m 0755 "$(dirname "$dest")"
        printf '%s\n' "$rendered" > "$dest"
        chmod "$mode" "$dest"
        log_changed "rendered $dest"
    fi
}

# fs_install_tree <src-dir> <dest-root> <mode>
# Install every regular file under a declared tree, preserving relative paths.
fs_install_tree() {
    local srcdir="$1" destroot="$2" mode="$3"
    [ -d "$srcdir" ] || log_die "declared tree missing from the repository: $srcdir"
    local f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$srcdir"/}"
        fs_install "$f" "$destroot/$rel" "$mode"
    done < <(find "$srcdir" -type f -print0)
}

# fs_ensure_dir <path> <mode> [owner:group]
fs_ensure_dir() {
    local path="$1" mode="$2" owner="${3:-root:root}"
    if [ -d "$path" ]; then
        local cur_mode cur_owner changed=0
        cur_mode=$(stat -c '%a' "$path")
        cur_owner=$(stat -c '%U:%G' "$path")
        [ "0$cur_mode" = "$mode" ] || { chmod "$mode" "$path"; changed=1; }
        [ "$cur_owner" = "$owner" ] || { chown "$owner" "$path"; changed=1; }
        if [ "$changed" = 1 ]; then log_changed "corrected $path"; else log_ok "$path current"; fi
    else
        install -d -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$path" \
            || log_die "cannot create $path"
        log_changed "created $path"
    fi
}

# fs_enable_unit <unit>...
# Enable system units that are not already enabled. Never --now: the converger
# declares state, and starting is the unit's own business at boot or below.
fs_enable_unit() {
    local u pending=()
    for u in "$@"; do
        systemctl is-enabled --quiet "$u" 2>/dev/null || pending+=("$u")
    done
    if [ ${#pending[@]} -eq 0 ]; then
        log_ok "units already enabled (${*})"
    else
        systemctl enable "${pending[@]}" >/dev/null 2>&1 \
            || log_die "cannot enable ${pending[*]}"
        log_changed "enabled ${pending[*]}"
    fi
}

# fs_enable_user_unit <user> <unit>...
# The agent box's timers run in the administrative user's own manager, so they
# are enabled globally rather than per-session.
fs_enable_user_unit() {
    local u pending=()
    for u in "$@"; do
        [ -L "/etc/systemd/user/timers.target.wants/$u" ] \
            || [ -L "/etc/systemd/user/default.target.wants/$u" ] \
            || [ -L "/etc/systemd/user/sockets.target.wants/$u" ] || pending+=("$u")
    done
    if [ ${#pending[@]} -eq 0 ]; then
        log_ok "user units already enabled (${*})"
    else
        systemctl --global enable "${pending[@]}" >/dev/null 2>&1 \
            || log_die "cannot enable user units ${pending[*]}"
        log_changed "enabled user units ${pending[*]}"
    fi
}

# fs_daemon_reload — reload only when a unit file actually changed this run.
fs_daemon_reload() {
    if [ "${FS_UNITS_DIRTY:-0}" = 1 ]; then
        systemctl daemon-reload
        FS_UNITS_DIRTY=0
    fi
}
