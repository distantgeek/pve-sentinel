#!/usr/bin/env python3
"""pve-sentinel — LLM-driven security advisory agent for Proxmox VE."""

import subprocess
import sys


def banner() -> str:
    """Generate the pve-sentinel ASCII banner via pyfiglet if available."""
    try:
        result = subprocess.run(
            ["pyfiglet", "-f", "smslant", "PVE-SENTINEL"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.rstrip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback banner
    return r"""
   ___ _   ______    _________  _____________  ________
  / _ \ | / / __/___/ __/ __/ |/ /_  __/  _/ |/ / __/ /
 / ___/ |/ / _//___/\ \/ _//    / / / _/ //    / _// /__
/_/   |___/___/   /___/___/_/|_/ /_/ /___/_/|_/___/____/
"""


def main() -> None:
    print(banner())
    print("pve-sentinel v0.1.0 — AI advisory agent for Proxmox VE")
    print()
    print("Status: initializing...")
    print("Run /help for available commands.")
    print()


if __name__ == "__main__":
    main()
