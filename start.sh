#!/usr/bin/env bash
# Lag Lens launcher.
#
#   bash start.sh                 run (fast doctor, then monitor; restart loop)
#   bash start.sh --doctor        full doctor table
#   bash start.sh --version       print the version
#   ... see docs/BUILD_PLAN.md §3.7 for every command.
#
# Behaviour:
#   * cd to its own directory (the repository / zip root);
#   * pick a Python >= 3.9: $LAGLENS_PYTHON, python3 on PATH,
#     /opt/homebrew/bin/python3, /usr/local/bin/python3, /usr/bin/python3;
#   * run  "$PY" -I -X utf8 run.py "$@";
#   * for the `run` command (plain or --resume) only: on a non-zero exit,
#     sleep 3 s and restart with --resume "$(cat sessions/.last)", at most
#     20 restarts/hour. One-shot subcommands (--doctor, --report, ...) run once.
#   * SIGINT/SIGTERM are forwarded to the child as SIGTERM and start.sh waits
#     for the child to finish its shutdown before returning.
#
# LAGLENS_DRYRUN=1 prints the chosen interpreter and exits 0 (used by tests).

set -u

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

# ---------------------------------------------------------------------------
# Python discovery
# ---------------------------------------------------------------------------
py_ok() {
    # $1 = candidate path; true when it is an executable Python >= 3.9
    [ -n "$1" ] && [ -x "$1" ] || return 1
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}

PY=""
candidates=()
[ -n "${LAGLENS_PYTHON:-}" ] && candidates+=("$LAGLENS_PYTHON")
if path_py="$(command -v python3 2>/dev/null)"; then
    candidates+=("$path_py")
fi
candidates+=(/opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3)

for c in "${candidates[@]}"; do
    if py_ok "$c"; then
        PY="$c"
        break
    fi
done

if [ -z "$PY" ]; then
    echo "Lag Lens needs Python 3.9 or newer and none was found." >&2
    case "$(uname -s)" in
        Darwin) echo "On macOS run:  xcode-select --install   (installs Apple's /usr/bin/python3)" >&2 ;;
        *)      echo "Install python3 with your package manager (e.g. sudo dnf install python3)." >&2 ;;
    esac
    exit 1
fi

if [ "${LAGLENS_DRYRUN:-0}" = "1" ]; then
    echo "$PY"
    exit 0
fi

# ---------------------------------------------------------------------------
# Decide whether this invocation is the long-running `run` command.
# `--resume sessions/<id>` is still a monitor run (BUILD_PLAN §3.7) and gets
# the restart loop; only the one-shot subcommands below run once.
# ---------------------------------------------------------------------------
loop=1
for a in "$@"; do
    case "$a" in
        --doctor|--selftest|--report|--export|--index|--loadtest|--docsis-dump|\
        --update|--check|--stop|--version|--help|-h)
            loop=0 ;;
    esac
done

# Forward SIGTERM/SIGINT to the child so the restart loop does not resurrect it.
child=0
stop_requested=0
on_signal() {
    stop_requested=1
    if [ "$child" -ne 0 ]; then
        kill -TERM "$child" 2>/dev/null
    fi
}
trap on_signal INT TERM

run_child() {
    # A background job gets /dev/null as stdin unless redirected explicitly; keep the
    # terminal attached when there is one so "Enter = Lag happened" works in the monitor.
    if [ -t 0 ]; then
        "$PY" -I -X utf8 run.py "$@" <&0 &
    else
        "$PY" -I -X utf8 run.py "$@" &
    fi
    child=$!
    # A trapped signal makes `wait` return at once (status 128+sig) while the
    # child is still shutting down (writer drain, final report, gzip). Keep
    # waiting until the child is really gone so its session is finalised
    # before this script returns and the pidfile is removed.
    wait "$child"
    rc=$?
    while kill -0 "$child" 2>/dev/null; do
        wait "$child"
        rc=$?
    done
    child=0
    return "$rc"
}

if [ "$loop" -eq 0 ]; then
    run_child "$@"
    exit $?
fi

# ---------------------------------------------------------------------------
# Restart loop (plain run): max 20 restarts per rolling hour
# ---------------------------------------------------------------------------
restarts=()
extra=()
while :; do
    run_child "$@" ${extra[@]+"${extra[@]}"}
    rc=$?
    if [ "$rc" -eq 3 ]; then
        exit 3  # another monitor already runs from this folder: do not restart
    fi
    if [ "$rc" -eq 0 ] || [ "$stop_requested" -eq 1 ]; then
        exit 0
    fi
    now=$(date +%s)
    keep=()
    for t in ${restarts[@]+"${restarts[@]}"}; do
        if [ $((now - t)) -lt 3600 ]; then keep+=("$t"); fi
    done
    restarts=(${keep[@]+"${keep[@]}"})
    if [ "${#restarts[@]}" -ge 20 ]; then
        echo "Lag Lens exited with status $rc and has already restarted 20 times in the last hour; giving up." >&2
        echo "Run  bash start.sh --doctor  and check sessions/<id>/log.txt for the reason." >&2
        exit "$rc"
    fi
    restarts+=("$now")
    extra=()
    if [ -s sessions/.last ]; then
        last="$(cat sessions/.last)"
        if [ -d "$last" ]; then
            extra=(--resume "$last")
        fi
    fi
    echo "Lag Lens exited with status $rc; restarting in 3 s (${#restarts[@]}/20 this hour)${extra[*]+ with ${extra[*]}}" >&2
    sleep 3
done
