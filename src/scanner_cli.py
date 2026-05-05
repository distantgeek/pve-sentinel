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

    cve_cfg = cfg.get("cve", {})

    db = Database(cfg["storage"]["db_path"])
    scanner = CVEScanner(
        db,
        nvd_api_key=cve_cfg.get("nvd_api_key"),
        nvd_rate_limit=cve_cfg.get("nvd_rate_limit", 5),
        mitre_enabled=cve_cfg.get("mitre_api_enabled", True),
        exploitdb_enabled=cve_cfg.get("exploitdb_enabled", True),
        pve_security_enabled=cve_cfg.get("pve_security_enabled", True),
        pve_sa_feed_url=cve_cfg.get("pve_sa_feed_url"),
    )

    try:
        # Sync PVE security advisories first
        if cve_cfg.get("pve_security_enabled", True):
            new_advisories = scanner.sync_pve_advisories()
            if new_advisories:
                print(f"PVE-SA sync: {new_advisories} new advisories")

        # Host scan — packages will be populated by ProxmoxTools in Phase 5
        # For now, run the scan pipeline with empty packages to establish
        # the scan log entry and fetch new CVEs from NVD.
        result = scanner.scan_host(packages=[])
        print(f"Host scan: {result['cves_found']} CVEs found, "
              f"{result['packages_checked']} packages checked, "
              f"{result['duration']:.1f}s")

        # Local LXC package scan (runs inside the LXC itself)
        lxc_result = scanner.scan_local_packages(packages=[])
        print(f"LXC scan: {lxc_result['cves_matched']} CVE matches, "
              f"{lxc_result['packages_checked']} packages checked, "
              f"{lxc_result['duration']:.1f}s")

        # Print matched CVEs if any
        if lxc_result.get("matched_cves"):
            print("\nMatched CVEs:")
            for m in lxc_result["matched_cves"][:20]:  # Limit output
                print(f"  {m['cve_id']} — {m['package']} {m['version']} "
                      f"({m['severity']}, CVSS {m['cvss_score']})")
            if len(lxc_result["matched_cves"]) > 20:
                print(f"  ... and {len(lxc_result['matched_cves']) - 20} more")
    finally:
        scanner.close()


if __name__ == "__main__":
    main()
