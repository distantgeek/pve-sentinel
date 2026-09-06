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

from src.config import load_config  # noqa: E402
from src.cve_scanner import CVEScanner  # noqa: E402
from src.database import Database  # noqa: E402
from src.proxmox_tools import ProxmoxTools  # noqa: E402


def _get_host_packages(cfg: dict) -> list[dict[str, str]]:
    """Fetch installed packages from the Proxmox host via the API.

    Returns an empty list (with a warning) if the Proxmox API is not
    configured or unreachable, so the scheduled scan never hard-fails
    on host connectivity problems.
    """
    pmx = cfg.get("proxmox", {})
    if not pmx.get("host") or not pmx.get("token_value"):
        print("Proxmox host not configured — skipping host package scan.", file=sys.stderr)
        return []

    try:
        tools = ProxmoxTools(
            host=pmx["host"],
            user=pmx.get("user", ""),
            token_name=pmx.get("token_name", ""),
            token_value=pmx["token_value"],
            node=pmx.get("node", ""),
            verify_ssl=pmx.get("verify_ssl", True),
        )
        packages = tools.get_host_packages()
        if not packages:
            print("Warning: Proxmox host returned no installed packages.", file=sys.stderr)
        return packages
    except Exception as e:
        print(f"Warning: could not fetch host packages from Proxmox API: {e}", file=sys.stderr)
        return []


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

        # Host scan — enumerate the Proxmox host's installed packages via the
        # API so CVEs are matched against the real host package inventory.
        host_packages = _get_host_packages(cfg)
        result = scanner.scan_host(packages=host_packages)
        print(
            f"Host scan: {result['cves_found']} CVEs found, "
            f"{result['packages_checked']} packages checked, "
            f"{result['duration']:.1f}s"
        )

        # Local LXC package scan (runs inside the LXC itself)
        lxc_result = scanner.scan_local_packages(packages=[])
        print(
            f"LXC scan: {lxc_result['cves_matched']} CVE matches, "
            f"{lxc_result['packages_checked']} packages checked, "
            f"{lxc_result['duration']:.1f}s"
        )

        # Print matched CVEs if any
        if lxc_result.get("matched_cves"):
            print("\nMatched CVEs:")
            for m in lxc_result["matched_cves"][:20]:  # Limit output
                print(
                    f"  {m['cve_id']} — {m['package']} {m['version']} "
                    f"({m['severity']}, CVSS {m['cvss_score']})"
                )
            if len(lxc_result["matched_cves"]) > 20:
                print(f"  ... and {len(lxc_result['matched_cves']) - 20} more")
    finally:
        scanner.close()


if __name__ == "__main__":
    main()
