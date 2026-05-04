"""CLI entry point for scheduled CVE scans (systemd timer target).

This module is invoked by systemd timers, not interactively.
It runs a host-level CVE scan and logs results to the database.
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.config import load_config
from src.database import Database
from src.cve_scanner import CVEScanner


def main() -> None:
    """Run a scheduled CVE scan."""
    try:
        cfg = load_config()
    except (FileNotFoundError, ValueError) as e:
        print(f"Config error: {e}", file=sys.stderr)
        sys.exit(1)

    db = Database(cfg["storage"]["db_path"])
    scanner = CVEScanner(
        db,
        nvd_rate_limit=cfg.get("cve", {}).get("nvd_rate_limit", 5),
        mitre_enabled=cfg.get("cve", {}).get("mitre_api_enabled", True),
        exploitdb_enabled=cfg.get("cve", {}).get("exploitdb_enabled", True),
        pve_security_enabled=cfg.get("cve", {}).get("pve_security_enabled", True),
    )

    try:
        # Host scan — packages will be populated by ProxmoxTools in Phase 5
        # For now, run the scan pipeline with empty packages to establish
        # the scan log entry and fetch new CVEs from NVD.
        result = scanner.scan_host(packages=[])
        print(f"Scan complete: {result['cves_found']} CVEs found, "
              f"{result['packages_checked']} packages checked, "
              f"{result['duration']:.1f}s")
    finally:
        scanner.close()


if __name__ == "__main__":
    main()
