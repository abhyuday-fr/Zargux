#!/usr/bin/env python3
"""
zargux.py — Zargux CLI prototype

Runs ON the target server (the VM), not on your host. It ties together
everything built so far: PSI-based pressure reading, and per-process
origin checks (the "which processes are actually suspicious" logic).

Subcommands:
  scan <pid>          One-shot verdict for a single process.
  watch [--interval N] Live view: system pressure + a table of every
                        process whose origin looks unusual (WATCH/HIGH).
                        CLEAR processes are hidden to keep the view readable.
  demo                Runs the three-case story end to end for a
                        presentation: legit run, dropped-copy run, and a
                        negative control — with a clean side-by-side
                        summary at the end. Requires sudo (spawns
                        processes via systemd-run and reads other users'
                        /proc/<pid>/exe).

Usage:
  sudo python3 zargux.py scan <pid>
  sudo python3 zargux.py watch
  sudo python3 zargux.py demo
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import time

SUSPICIOUS_PREFIXES = ("/dev/shm/", "/tmp/", "/var/tmp/")

# ---- persistence --------------------------------------------------------

FINDINGS_FILE = "findings.json"

# maps our internal verdicts onto the severity labels the viewer expects
SEVERITY_MAP = {"HIGH": "High", "WATCH": "Medium", "CLEAR": "Info"}

PSI_FILE = "psi.json"


def save_finding(summary: str, severity: str = "Info"):
    data = []
    if os.path.exists(FINDINGS_FILE):
        with open(FINDINGS_FILE) as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    now = datetime.datetime.now()
    data.append(
        {
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "summary": summary,
            "severity": severity,
        }
    )
    with open(FINDINGS_FILE, "w") as f:
        json.dump(data[-100:], f, indent=2)


def save_psi_snapshot():
    """Write the current PSI reading to a small file the dashboard can poll."""
    psi = read_psi()
    if psi is None:
        return
    with open(PSI_FILE, "w") as f:
        json.dump(
            {
                "avg10": psi.get("avg10", "?"),
                "avg60": psi.get("avg60", "?"),
                "avg300": psi.get("avg300", "?"),
                "updated": datetime.datetime.now().strftime("%H:%M:%S"),
            },
            f,
        )


# ---- colors -----------------------------------------------------------

IS_TTY = sys.stdout.isatty()


def c(code, text):
    if not IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t):
    return c("31;1", t)


def yellow(t):
    return c("33;1", t)


def green(t):
    return c("32;1", t)


def cyan(t):
    return c("36;1", t)


def dim(t):
    return c("2", t)


def bold(t):
    return c("1", t)


VERDICT_COLOR = {"HIGH": red, "WATCH": yellow, "CLEAR": green}


# ---- core detection logic (same as detector.py) ------------------------


def read_exe_path(pid: str):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except PermissionError:
        return None


def check_dpkg_owned(path: str) -> bool:
    result = subprocess.run(
        ["dpkg", "-S", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def classify(exe_path: str):
    deleted = exe_path.endswith(" (deleted)")
    clean_path = exe_path[: -len(" (deleted)")] if deleted else exe_path

    if deleted:
        return "HIGH", f"deleted from disk while running ({clean_path})"
    if clean_path.startswith(SUSPICIOUS_PREFIXES):
        return "HIGH", f"running from a writable temp location ({clean_path})"
    if check_dpkg_owned(clean_path):
        return "CLEAR", f"package-managed ({clean_path})"
    return "WATCH", f"unpackaged, but not in a writable temp location ({clean_path})"


def read_psi():
    try:
        with open("/proc/pressure/cpu") as f:
            some_line = f.readline().strip()
        fields = dict(kv.split("=") for kv in some_line.split()[1:])
        return fields
    except Exception:
        return None


def cpu_percent(pid: str):
    try:
        out = subprocess.run(
            ["ps", "-p", pid, "-o", "%cpu="],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
        return out or "0.0"
    except Exception:
        return "?"


# ---- scan ---------------------------------------------------------------


def cmd_scan(pid: str):
    exe = read_exe_path(pid)
    if exe is None:
        print(red(f"error: pid {pid} not found, exited, or permission denied"))
        sys.exit(1)

    verdict, reason = classify(exe)
    colorize = VERDICT_COLOR[verdict]

    print(bold(f"\n  Zargux scan — pid {pid}"))
    print(f"  {dim('exe:')}     {exe}")
    print(f"  {dim('verdict:')} {colorize(verdict)}")
    print(f"  {dim('reason:')}  {reason}\n")

    save_finding(f"pid {pid} ({exe}): {reason}", SEVERITY_MAP[verdict])


# ---- watch ---------------------------------------------------------------


def list_pids():
    return [p for p in os.listdir("/proc") if p.isdigit()]


def cmd_watch(interval: float):
    seen = {}  # pid -> last verdict logged, so watch doesn't spam the same finding every refresh
    try:
        while True:
            os.system("clear")
            width = shutil.get_terminal_size((80, 20)).columns
            print(bold(cyan("=" * width)))
            print(
                bold(cyan("  ZARGUX — live watch")),
                dim(f"  (ctrl-c to stop, refresh {interval}s)"),
            )
            print(bold(cyan("=" * width)))

            psi = read_psi()
            if psi:
                print(
                    f"\n  {bold('CPU pressure')}  avg10={psi.get('avg10', '?')}  "
                    f"avg60={psi.get('avg60', '?')}  avg300={psi.get('avg300', '?')}"
                )
            else:
                print(f"\n  {yellow('CPU pressure unavailable (PSI not readable)')}")
            save_psi_snapshot()

            print(f"\n  {bold('Flagged processes')} {dim('(CLEAR processes hidden)')}")
            print(f"  {'PID':<8}{'CPU%':<8}{'VERDICT':<9}EXE / REASON")
            print("  " + "-" * (width - 2))

            found_any = False
            for pid in sorted(list_pids(), key=int):
                exe = read_exe_path(pid)
                if exe is None:
                    continue
                verdict, reason = classify(exe)
                if verdict == "CLEAR":
                    continue
                found_any = True
                colorize = VERDICT_COLOR[verdict]
                cpu = cpu_percent(pid)
                print(f"  {pid:<8}{cpu:<8}{colorize(verdict):<18}{reason}")

                # only log a finding the first time we see this pid at this
                # verdict, so a long-running flagged process doesn't spam
                # findings.json with a duplicate row every refresh
                if seen.get(pid) != verdict:
                    save_finding(f"pid {pid}: {reason}", SEVERITY_MAP[verdict])
                    seen[pid] = verdict

            if not found_any:
                print(dim("  (nothing flagged right now)"))

            print()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopped.")


# ---- demo ---------------------------------------------------------------


def systemd_run(unit: str, *cmd_args):
    subprocess.run(
        ["sudo", "systemd-run", f"--unit={unit}", "--collect", "--"] + list(cmd_args),
        check=True,
    )


def get_main_pid(unit: str):
    out = subprocess.run(
        ["systemctl", "show", "-p", "MainPID", "--value", f"{unit}.service"],
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    return out if out and out != "0" else None


def cmd_demo():
    print(bold(cyan("\n=== ZARGUX DEMO ===\n")))
    print("This runs three cases and shows how origin-based detection")
    print("tells them apart, even when CPU load looks identical.\n")

    # cleanup any leftovers from a previous demo run
    subprocess.run(
        [
            "sudo",
            "systemctl",
            "stop",
            "zargux-demo-legit.service",
            "zargux-demo-shm.service",
            "zargux-demo-control.service",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sudo", "rm", "-f", "/dev/shm/stress-copy"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["bash", "-c", "rm -rf /home/ubuntu/bin"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    results = []

    # Case 1: legitimate
    print(f"{dim('[1/3]')} launching legitimate stress-ng from /usr/bin ...")
    systemd_run("zargux-demo-legit", "stress-ng", "--cpu", "4", "--timeout", "30s")
    time.sleep(3)
    pid1 = get_main_pid("zargux-demo-legit")
    if pid1:
        exe1 = read_exe_path(pid1)
        v1, r1 = classify(exe1)
        results.append(("Legitimate (/usr/bin)", pid1, exe1, v1, r1))
        save_finding(f"pid {pid1} ({exe1}): {r1}", SEVERITY_MAP[v1])

    # Case 2: dropped copy in /dev/shm
    print(f"{dim('[2/3]')} copying the same binary into /dev/shm and running it ...")
    subprocess.run(
        ["sudo", "cp", "/usr/bin/stress-ng", "/dev/shm/stress-copy"], check=True
    )
    subprocess.run(["sudo", "chmod", "+x", "/dev/shm/stress-copy"], check=True)
    systemd_run(
        "zargux-demo-shm", "/dev/shm/stress-copy", "--cpu", "4", "--timeout", "30s"
    )
    time.sleep(3)
    pid2 = get_main_pid("zargux-demo-shm")
    if pid2:
        exe2 = read_exe_path(pid2)
        v2, r2 = classify(exe2)
        results.append(("Dropped copy (/dev/shm)", pid2, exe2, v2, r2))
        save_finding(f"pid {pid2} ({exe2}): {r2}", SEVERITY_MAP[v2])

    # Case 3: negative control — legit but unpackaged, normal location
    print(f"{dim('[3/3]')} launching a legitimate but unpackaged tool from ~/bin ...")
    subprocess.run(
        [
            "bash",
            "-c",
            "mkdir -p /home/ubuntu/bin && cp /bin/sleep /home/ubuntu/bin/my-legit-tool",
        ],
        check=True,
    )
    systemd_run("zargux-demo-control", "/home/ubuntu/bin/my-legit-tool", "30")
    time.sleep(2)
    pid3 = get_main_pid("zargux-demo-control")
    if pid3:
        exe3 = read_exe_path(pid3)
        v3, r3 = classify(exe3)
        results.append(("Negative control (~/bin)", pid3, exe3, v3, r3))
        save_finding(f"pid {pid3} ({exe3}): {r3}", SEVERITY_MAP[v3])

    save_psi_snapshot()

    # Summary table
    print(bold(cyan("\n=== RESULTS ===\n")))
    print(f"  {'CASE':<26}{'PID':<8}{'VERDICT':<18}EXE")
    print("  " + "-" * 70)
    for label, pid, exe, verdict, reason in results:
        colorize = VERDICT_COLOR[verdict]
        print(f"  {label:<26}{pid:<8}{colorize(verdict):<18}{exe}")

    # cleanup
    subprocess.run(
        [
            "sudo",
            "systemctl",
            "stop",
            "zargux-demo-legit.service",
            "zargux-demo-shm.service",
            "zargux-demo-control.service",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sudo", "rm", "-f", "/dev/shm/stress-copy"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ---- entry point ----------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        prog="zargux", description="Zargux incident-origin detector (prototype)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Check a single process by PID")
    p_scan.add_argument("pid")

    p_watch = sub.add_parser(
        "watch", help="Live view of pressure and flagged processes"
    )
    p_watch.add_argument("--interval", type=float, default=3.0)

    sub.add_parser("demo", help="Run the full three-case demo end to end")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args.pid)
    elif args.command == "watch":
        cmd_watch(args.interval)
    elif args.command == "demo":
        cmd_demo()


if __name__ == "__main__":
    main()
