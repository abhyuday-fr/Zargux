#!/usr/bin/env bash
# evidence.sh — Zargux demo live evidence viewer (PID-file based)
# Usage:
#   ./evidence.sh            single snapshot, prints once and exits (good for narrating)
#   ./evidence.sh watch [N]  loops every N seconds (default 5)

set -euo pipefail

VM="zargux-lab"
MODE="${1:-once}"
INTERVAL="${2:-5}"

exec_vm() {
    multipass exec "$VM" -- bash -c "$1"
}

show_once() {
    echo "=================== ZARGUX LIVE EVIDENCE ==================="
    date

    echo
    echo "--- CPU pressure (/proc/pressure/cpu) ---"
    exec_vm "cat /proc/pressure/cpu" || echo "(unavailable)"

    echo
    echo "--- process table (by recorded PID, not by name) ---"
    exec_vm "for f in genuine loud quiet; do
        if [ -f /tmp/\$f.pid ]; then
            pid=\$(cat /tmp/\$f.pid)
            if kill -0 \$pid 2>/dev/null; then
                cpu=\$(ps -o %cpu= -p \$pid 2>/dev/null | tr -d ' ')
                exe=\$(readlink /proc/\$pid/exe 2>/dev/null || echo '?')
                printf '%-8s pid=%-6s cpu=%-5s exe=%s\n' \"\$f\" \"\$pid\" \"\$cpu\" \"\$exe\"
            else
                printf '%-8s pid=%-6s (finished)\n' \"\$f\" \"\$pid\"
            fi
        else
            printf '%-8s (not started — run attack.sh start)\n' \"\$f\"
        fi
    done"

    echo
    echo "=============================================================="
}

if [ "$MODE" = "watch" ]; then
    while true; do
        clear
        show_once
        echo "(refreshing every ${INTERVAL}s, ctrl-c to stop)"
        sleep "$INTERVAL"
    done
else
    show_once
    echo "(run './evidence.sh' again for an updated snapshot, or './evidence.sh watch' to loop)"
fi
