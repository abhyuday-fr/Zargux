#!/usr/bin/env bash
# attack.sh — Zargux demo attack simulation (PID-file based, no name matching)
# Usage: ./attack.sh {start|stop|status}

set -euo pipefail

VM="zargux-lab"
DURATION=120   # seconds the CPU loads run for — generous so you have time to talk

exec_vm() {
    multipass exec "$VM" -- bash -c "$1"
}

setup() {
    echo "[setup] copying attacker binaries into writable locations on $VM..."
    exec_vm "sudo cp /usr/bin/stress-ng /dev/shm/.kworker && sudo chmod +x /dev/shm/.kworker"
    exec_vm "sudo cp /usr/bin/sleep /tmp/.svc-helper && sudo chmod +x /tmp/.svc-helper"
    echo "[setup] done."
}

start() {
    setup

    echo "[start] launching GENUINE baseline (stress-ng from /usr/bin)..."
    exec_vm "nohup stress-ng --cpu 4 --timeout ${DURATION}s > /tmp/genuine.log 2>&1 & echo \$! > /tmp/genuine.pid"

    echo "[start] launching LOUD attacker (copy of stress-ng from /dev/shm)..."
    exec_vm "nohup /dev/shm/.kworker --cpu 4 --timeout ${DURATION}s > /tmp/loud.log 2>&1 & echo \$! > /tmp/loud.pid"

    echo "[start] launching QUIET attacker (copy of sleep from /tmp)..."
    exec_vm "nohup /tmp/.svc-helper 300 > /tmp/quiet.log 2>&1 & echo \$! > /tmp/quiet.pid"

    sleep 1
    echo
    echo "[start] PIDs recorded:"
    exec_vm "echo genuine=\$(cat /tmp/genuine.pid 2>/dev/null || echo '?')"
    exec_vm "echo loud=\$(cat /tmp/loud.pid 2>/dev/null || echo '?')"
    exec_vm "echo quiet=\$(cat /tmp/quiet.pid 2>/dev/null || echo '?')"
    echo
    echo "[start] all three processes launched. Run ./evidence.sh now (in another terminal, or repeatedly here)."
}

stop() {
    echo "[stop] killing demo processes by recorded PID..."
    exec_vm "for f in genuine loud quiet; do
        if [ -f /tmp/\$f.pid ]; then
            pid=\$(cat /tmp/\$f.pid)
            kill \$pid 2>/dev/null || true
        fi
    done"
    echo "[stop] cleaning up dropped binaries and pid files..."
    exec_vm "sudo rm -f /dev/shm/.kworker /tmp/.svc-helper /tmp/genuine.pid /tmp/loud.pid /tmp/quiet.pid /tmp/genuine.log /tmp/loud.log /tmp/quiet.log"
    echo "[stop] done. VM state cleared."
}

status() {
    echo "[status] checking recorded PIDs on $VM:"
    exec_vm "for f in genuine loud quiet; do
        if [ -f /tmp/\$f.pid ]; then
            pid=\$(cat /tmp/\$f.pid)
            if kill -0 \$pid 2>/dev/null; then
                echo \"\$f: pid=\$pid ALIVE exe=\$(readlink /proc/\$pid/exe 2>/dev/null || echo '?')\"
            else
                echo \"\$f: pid=\$pid DEAD (already finished)\"
            fi
        else
            echo \"\$f: no pid file (not started)\"
        fi
    done"
}

case "${1:-}" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
