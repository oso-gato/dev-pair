# shellcheck shell=sh  # sourced by the login shell, never executed — no shebang by design
# Land in the durable session on login. Shared by both components.
#
# The host and the dev-container are both reached by ssh and by mosh, and on
# both the work must outlive the connection. So both attach to tmux on an
# interactive login rather than handing over a bare shell that dies with the
# socket.
#
# Each login joins the shared work as its own client-scoped session inside a
# session GROUP rather than attaching to one session directly. Sessions in a
# group share their windows, so every device sees the same work, while each
# device keeps its own current window and its own attachment. Attaching every
# client to a single session instead would make every client share one
# geometry, and a second device of a different size would repaint every other
# device onto a foreign grid — the objective's "from any authorized device"
# broken by the second device. The geometry rules for the case two devices do
# land on the same window live in /etc/tmux.conf.
#
# The group's first session is created detached and is never attached to. It is
# what owns the windows, so the work survives every client leaving; the
# per-login sessions carry destroy-unattached so a disconnected device leaves
# no session behind to collect.
#
# Guarded three ways, because this file runs for more than interactive humans:
# a non-interactive shell (scp, `ssh nox <command>`, rsync) must not be hijacked,
# and a shell already inside tmux must not nest.
case "$-" in
    *i*) ;;
    *) return ;;
esac
[ -n "${TMUX:-}" ] && return
[ -n "${DEV_PAIR_NO_TMUX:-}" ] && return
command -v tmux >/dev/null 2>&1 || return

_pair_group="${DEV_PAIR_SESSION:-main}"
tmux has-session -t "$_pair_group" 2>/dev/null \
    || tmux new-session -d -s "$_pair_group" 2>/dev/null \
    || true
exec tmux new-session -t "$_pair_group" -s "${_pair_group}-$$" \
     \; set-option destroy-unattached on
