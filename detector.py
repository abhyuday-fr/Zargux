#!/usr/bin/env python3
"""
detector.py — Zargux origin-check prototype

Usage: python3 detector.py <pid>

Reads /proc/<pid>/exe to find where the running binary actually lives,
checks whether that binary is owned by an installed package (dpkg),
and produces a verdict based on origin — not on CPU load.

Verdicts:
  HIGH    — binary runs from a writable temp location, or has been
            deleted from disk while still running.
  WATCH   — binary is not owned by any installed package, but lives
            in a normal, non-writable-temp location (e.g. /usr/local/bin,
            ~/bin, /opt). Not inherently malicious — plenty of legitimate
            software isn't installed via a package manager — but worth
            a human glance since it can't be provenance-checked.
  CLEAR   — binary is owned by an installed package and lives in a
            normal location.
"""

import os
import subprocess
import sys

# Locations an attacker can write to and immediately execute from.
SUSPICIOUS_PREFIXES = ("/dev/shm/", "/tmp/", "/var/tmp/")


def read_exe_path(pid: str) -> str:
    """Resolve /proc/<pid>/exe. Raises on failure with a clear reason."""
    link = f"/proc/{pid}/exe"
    try:
        return os.readlink(link)
    except FileNotFoundError:
        raise SystemExit(
            f"error: no such process (pid {pid} not found or already exited)"
        )
    except PermissionError:
        raise SystemExit(
            f"error: permission denied reading {link} — "
            f"try running with sudo (needed to inspect processes you don't own)"
        )


def check_dpkg_owned(path: str) -> bool:
    """Return True if the real (non-deleted) path is owned by an installed package."""
    result = subprocess.run(
        ["dpkg", "-S", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def classify(exe_path: str) -> tuple[str, str]:
    """Return (verdict, reason) for the given exe path."""
    deleted = exe_path.endswith(" (deleted)")
    clean_path = exe_path[: -len(" (deleted)")] if deleted else exe_path

    if deleted:
        return (
            "HIGH",
            f"binary has been deleted from disk while still running ({clean_path})",
        )

    if clean_path.startswith(SUSPICIOUS_PREFIXES):
        return "HIGH", f"binary runs from a writable temp location ({clean_path})"

    owned = check_dpkg_owned(clean_path)
    if owned:
        return "CLEAR", f"binary is owned by an installed package ({clean_path})"

    return (
        "WATCH",
        f"binary is not package-managed, but not in a writable temp location ({clean_path})",
    )


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <pid>", file=sys.stderr)
        sys.exit(1)

    pid = sys.argv[1]
    exe_path = read_exe_path(pid)
    verdict, reason = classify(exe_path)

    print(f"pid:     {pid}")
    print(f"exe:     {exe_path}")
    print(f"verdict: {verdict}")
    print(f"reason:  {reason}")


if __name__ == "__main__":
    main()
