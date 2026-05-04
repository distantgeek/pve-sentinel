"""CVE scanner — multi-source vulnerability intelligence.

Data sources:
    1. NVD API (primary CVE feed)
    2. MITRE CVE (enrichment, references, workarounds)
    3. Exploit-DB (public exploit detection → severity escalation)
    4. Proxmox PVE-SA (patch status correlation)
"""

import json
import time
from datetime import date, datetime, timedelta
from typing import Any, Optional

import httpx
import requests

from .database import Database


class CVEScanner:
    """Multi-source CVE intelligence engine."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MITRE_API = "https://cveawg.mitre.org/api/cve"
    EXPLOITDB_SEARCH = "https://exploit-db.com/search"

    def __init__(
        self,
        db: Database,
        nvd_rate_limit: int = 5,
        mitre_enabled: bool = True,
        exploitdb_enabled: bool = True,
        pve_security_enabled: bool = True,
    ):
        self.db = db
        self.nvd_rate_limit = nvd_rate_limit
        self.mitre_enabled = mitre_enabled
        self.exploitdb_enabled = exploitdb_enabled
        self.pve_security_enabled = pve_security_enabled

    # ── NVD API ──────────────────────────────────────────

    def fetch_nvd_cves(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        severity: Optional[str] = None,
    ) -> list[dict]:
        """Fetch CVEs from NVD within a date range.

        Args:
            start_date: Beginning of range (defaults to last scan date).
            end_date: End of range (defaults to today).
            severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL).

        Returns:
            List of normalized CVE dicts.
        """
        if end_date is None:
            end_date = date.today()
        if start_date is None:
            last = self.db.get_last_scan_date("host")
            if last:
                start_date = last
            else:
                start_date = end_date - timedelta(days=1)

        params: dict[str, Any] = {
            "pubStartDate": f"{start_date.isoformat()}T00:00:00.000",
            "pubEndDate": f"{end_date.isoformat()}T23:59:59.999",
            "resultsPerPage": 2000,
        }
        if severity:
            params["cvssV3Severity"] = severity

        cves = []
        start_index = 0
        total = None

        while total is None or start_index < total:
            params["startIndex"] = start_index
            resp = requests.get(self.NVD_API, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if total is None:
                total = data.get("totalResults", 0)

            for vuln in data.get("vulnerabilities", []):
                cve_item = vuln.get("cve", {})
                cves.append(self._normalize_nvd(cve_item))

            start_index += len(data.get("vulnerabilities", []))

            # Rate limit: NVD allows ~5 req/6s without API key
            time.sleep(6.0 / self.nvd_rate_limit)

        return cves

    def _normalize_nvd(self, cve_item: dict) -> dict:
        """Normalize an NVD CVE record into our schema."""
        cve_id = cve_item.get("id", "")

        # Extract CVSS v3 score
        metrics = cve_item.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        cvss_score = None
        severity = ""
        if cvss_data:
            cvss = cvss_data[0].get("cvssData", {})
            cvss_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "")

        # Extract description
        descriptions = cve_item.get("descriptions", [])
        desc_en = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_en = d.get("value", "")
                break

        # Extract affected configurations (CPE → package mapping)
        affected_package = ""
        fixed_version = ""
        configurations = cve_item.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        # Parse CPE: cpe:2.3:a:vendor:product:version:...
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            affected_package = parts[4]
                        if match.get("versionEndExcluding"):
                            fixed_version = match["versionEndExcluding"]

        return {
            "id": cve_id,
            "description": desc_en,
            "severity": severity,
            "cvss_score": cvss_score,
            "published": cve_item.get("published", ""),
            "modified": cve_item.get("lastModified", ""),
            "affected_package": affected_package,
            "fixed_version": fixed_version,
            "raw_json": json.dumps(cve_item),
        }

    # ── MITRE CVE Enrichment ─────────────────────────────

    def enrich_mitre(self, cve_id: str) -> dict:
        """Fetch MITRE CVE data for references and workarounds.

        MITRE often contains researcher notes, vendor references,
        and mitigation documentation not present in the NVD feed.
        """
        if not self.mitre_enabled:
            return {}

        try:
            resp = requests.get(f"{self.MITRE_API}/{cve_id}", timeout=15)
            if resp.status_code != 200:
                return {}
            data = resp.json()

            references = []
            for ref in data.get("references", []):
                references.append({
                    "url": ref.get("url", ""),
                    "tags": ref.get("tags", []),
                })

            return {
                "mitre_references": json.dumps(references[:10]),  # Top 10 refs
            }
        except requests.RequestException:
            return {}

    # ── Exploit-DB Check ─────────────────────────────────

    def check_exploitdb(self, cve_id: str) -> dict:
        """Check if a public exploit exists for this CVE.

        If an exploit exists, the severity escalates:
            CRITICAL → CRITICAL+ / HIGH → CRITICAL / MEDIUM → HIGH
        """
        if not self.exploitdb_enabled:
            return {}

        try:
            # Search Exploit-DB by CVE ID
            resp = requests.get(
                self.EXPLOITDB_SEARCH,
                params={"cve": cve_id},
                headers={"User-Agent": "pve-sentinel/0.1"},
                timeout=15,
            )
            if resp.status_code != 200:
                return {}

            text = resp.text.lower()
            has_exploit = cve_id.lower() in text

            if has_exploit:
                # Try to extract exploit type from search results
                exploit_type = "unknown"
                if "remote" in text:
                    exploit_type = "remote"
                elif "local" in text:
                    exploit_type = "local"
                elif "dos" in text:
                    exploit_type = "dos"

                verified = "verified" in text

                return {
                    "exploit_available": True,
                    "exploit_type": exploit_type,
                    "exploit_verified": verified,
                    "exploit_auth_required": "authenticated" in text,
                }
        except requests.RequestException:
            pass

        return {"exploit_available": False}

    # ── Sentinel Priority Computation ────────────────────

    def compute_priority(
        self,
        cve_severity: str,
        exploit_available: bool,
    ) -> str:
        """Compute sentinel priority from NVD severity + exploit status.

        Matrix:
            CRITICAL + exploit = CRITICAL+
            CRITICAL + no_expl  = CRITICAL
            HIGH     + exploit = CRITICAL
            HIGH     + no_expl  = HIGH
            MEDIUM   + exploit = HIGH
            MEDIUM   + no_expl  = MEDIUM
            LOW      + exploit = MEDIUM
            LOW      + no_expl  = LOW
        """
        if cve_severity == "CRITICAL" and exploit_available:
            return "CRITICAL+"
        if cve_severity == "CRITICAL":
            return "CRITICAL"
        if cve_severity == "HIGH" and exploit_available:
            return "CRITICAL"
        if cve_severity == "HIGH":
            return "HIGH"
        if cve_severity == "MEDIUM" and exploit_available:
            return "HIGH"
        if cve_severity == "MEDIUM":
            return "MEDIUM"
        if exploit_available:
            return "MEDIUM"
        return "LOW"

    # ── Host Scan Pipeline ───────────────────────────────

    def scan_host(
        self,
        packages: list[dict[str, str]],
        start_date: Optional[date] = None,
    ) -> dict[str, Any]:
        """Run a full host CVE scan pipeline.

        1. Update host package inventory
        2. Fetch new CVEs from NVD
        3. Enrich with MITRE + Exploit-DB
        4. Cross-reference packages with CVEs
        5. Compute priorities
        6. Return scan summary

        Returns:
            Scan summary dict.
        """
        started = datetime.now()

        # Update package inventory
        self.db.update_host_packages(packages)

        # Fetch CVEs
        cves = self.fetch_nvd_cves(start_date=start_date)
        new_cves = 0

        for cve_data in cves:
            cve_id = cve_data["id"]

            # Enrich with MITRE
            mitre = self.enrich_mitre(cve_id)
            cve_data.update(mitre)

            # Check exploit availability
            exploit = self.check_exploitdb(cve_id)
            cve_data.update(exploit)

            # Compute sentinel priority
            cve_data["sentinel_priority"] = self.compute_priority(
                cve_data.get("severity", ""),
                cve_data.get("exploit_available", False),
            )

            # Store CVE
            self.db.insert_cve(cve_data)
            new_cves += 1

            # Cross-reference with installed packages
            for pkg in packages:
                pkg_name = pkg.get("name", "").lower()
                match_name = cve_data.get("affected_package", "").lower()

                if pkg_name == match_name or pkg_name in match_name or match_name in pkg_name:
                    # Check Proxmox patch status
                    pve_status = self._check_pve_patch_status(cve_id, pkg_name)
                    if pve_status is None:
                        pve_status = {"pve_patch_status": "unknown"}

                    self.db.insert_cve_match({
                        "cve_id": cve_id,
                        "package_name": pkg_name,
                        "installed_version": pkg.get("version", ""),
                        "upstream_fixed_version": cve_data.get("fixed_version", ""),
                        "pve_patch_status": pve_status.get("pve_patch_status", "unknown"),
                        "pve_advisory_id": pve_status.get("pve_advisory_id", ""),
                        "pve_advisory_url": pve_status.get("pve_advisory_url", ""),
                        "impact_assessment": self._assess_impact(cve_data, pkg),
                        "exposure_level": cve_data.get("sentinel_priority", ""),
                        "mitigation_steps": self._format_mitigation(cve_data),
                    })

        elapsed = (datetime.now() - started).total_seconds()
        self.db.log_scan("host", new_cves, len(packages), elapsed)

        return {
            "scan_type": "host",
            "cves_found": new_cves,
            "packages_checked": len(packages),
            "duration": elapsed,
            "started": started.isoformat(),
        }

    # ── LXC Scan Pipeline ─────────────────────────────────

    def scan_lxc(self, lxc_id: str) -> Optional[dict[str, Any]]:
        """Scan a single LXC's package inventory against CVE database.

        Requires pct exec access (always available for LXCs).
        """
        # Refresh LXC package inventory
        from .proxmox_tools import ProxmoxTools
        # Package refresh happens externally — uses db from caller context
        started = datetime.now()

        # Get all CVEs in the database
        cves = self.db.get_new_cves_since(date.today() - timedelta(days=90))

        lxc_packages = None
        # Get packages from DB
        with self.db._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM lxc_packages WHERE lxc_id = ?",
                (lxc_id,),
            ).fetchall()
            lxc_packages = [dict(r) for r in rows]

        if not lxc_packages:
            return None

        matches = 0
        for pkg in lxc_packages:
            pkg_name = pkg.get("package_name", "").lower()
            for cve in cves:
                cve_pkg = cve.get("affected_package", "").lower()
                if pkg_name == cve_pkg or pkg_name in cve_pkg or cve_pkg in pkg_name:
                    self.db._connect().execute(
                        """INSERT OR REPLACE INTO lxc_cve_matches
                           (lxc_id, cve_id, package_name, installed_version, detected_at)
                           VALUES (?, ?, ?, ?, date('now'))""",
                        (lxc_id, cve["id"], pkg_name, pkg.get("version", "")),
                    )
                    matches += 1

        elapsed = (datetime.now() - started).total_seconds()

        return {
            "lxc_id": lxc_id,
            "packages_checked": len(lxc_packages),
            "cves_matched": matches,
            "duration": elapsed,
        }

    # ── Proxmox PVE-SA Check ─────────────────────────────

    def _check_pve_patch_status(self, cve_id: str, package: str) -> Optional[dict]:
        """Check if Proxmox has released a patch for this CVE.

        Queries the pve-security advisory database (local cache).
        Proxmox uses backported fixes, so the patched version number
        may differ from the upstream fix version.
        """
        if not self.pve_security_enabled:
            return None

        with self.db._connect() as conn:
            row = conn.execute(
                "SELECT * FROM pve_security_advisories WHERE cve_ids LIKE ?",
                (f"%{cve_id}%",),
            ).fetchone()

        if row:
            return {
                "pve_patch_status": "released",
                "pve_advisory_id": row["id"],
                "pve_advisory_url": row["raw_url"],
            }

        return {"pve_patch_status": "pending"}

    # ── Impact & Mitigation ──────────────────────────────

    def _assess_impact(self, cve: dict, pkg: dict) -> str:
        """Generate a human-readable impact assessment."""
        severity = cve.get("severity", "UNKNOWN")
        exploit = cve.get("exploit_available", False)
        description = cve.get("description", "")[:200]

        if exploit:
            return (
                f"Public exploit available. {description}. "
                f"Immediate mitigation recommended."
            )
        if severity == "CRITICAL":
            return f"Critical severity ({cve.get('cvss_score', '?')}). {description}."
        if severity == "HIGH":
            return f"High severity. {description}."
        return f"{severity} severity. {description}."

    def _format_mitigation(self, cve: dict) -> str:
        """Format mitigation steps as JSON."""
        steps = []

        if cve.get("pve_patch_status") == "released":
            steps.append({
                "action": "apt_update",
                "detail": "Proxmox patch available. Run: apt update && apt upgrade",
                "priority": "standard",
            })
        else:
            steps.append({
                "action": "monitor",
                "detail": "No Proxmox patch yet. Monitor pve-security mailing list.",
                "priority": "ongoing",
            })

        if cve.get("exploit_available"):
            steps.append({
                "action": "mitigate_now",
                "detail": "Public exploit exists. Deploy temporary mitigations.",
                "priority": "immediate",
            })

        return json.dumps(steps)
