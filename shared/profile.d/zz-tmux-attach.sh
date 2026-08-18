# shellcheck shell=sh  # sourced by the login shell, never executed — no shebang by design
# Land in the durable session on login. Shared by both components.
#
# The host and the dev-container are both reached by ssh and by mosh, and on
# both the work must outlive the connection. So both attach to tmux on an
# interactive login rather than handing over a bare shell that dies with the
# socket.
#
# The whole point of this component is that work outlives the connection, so an
# interactive login attaches to tmux rather than to a bare shell that dies with
# the socket. -A attaches if the session exists and creates it if not, so the
# first login and every reconnection after a roam take the same path.
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

exec tmux new-session -A -s "${DEV_PAIR_SESSION:-main}"
