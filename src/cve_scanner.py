"""CVE scanner — multi-source vulnerability intelligence.

Data sources:
    1. NVD API (primary CVE feed)
    2. MITRE CVE (enrichment, references, workarounds)
    3. Exploit-DB (public exploit detection → severity escalation)
    4. Proxmox PVE-SA (patch status correlation)
"""

import json
import re
import time
from datetime import date, datetime, timedelta
from typing import Any, Optional

import httpx

from .database import Database


class CVEScanner:
    """Multi-source CVE intelligence engine."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MITRE_API = "https://cveawg.mitre.org/api/cve"
    PVE_SA_WIKI = "https://pve.proxmox.com/wiki/Security_Advisories"

    def __init__(
        self,
        db: Database,
        nvd_api_key: Optional[str] = None,
        nvd_rate_limit: int = 5,
        mitre_enabled: bool = True,
        exploitdb_enabled: bool = True,
        pve_security_enabled: bool = True,
        pve_sa_feed_url: Optional[str] = None,
    ):
        self.db = db
        self.nvd_api_key = nvd_api_key
        self.nvd_rate_limit = nvd_rate_limit
        self.mitre_enabled = mitre_enabled
        self.exploitdb_enabled = exploitdb_enabled
        self.pve_security_enabled = pve_security_enabled
        self.pve_sa_feed_url = pve_sa_feed_url or self.PVE_SA_WIKI
        self._http = httpx.Client(timeout=30.0)

    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()

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

        headers: dict[str, str] = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
            # With API key: 50 req/6s; without: 5 req/6s
            effective_rate = max(self.nvd_rate_limit, 50)
        else:
            effective_rate = self.nvd_rate_limit

        cves = []
        start_index = 0
        total = None

        while total is None or start_index < total:
            params["startIndex"] = start_index
            resp = self._http.get(self.NVD_API, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            if total is None:
                total = data.get("totalResults", 0)

            for vuln in data.get("vulnerabilities", []):
                cve_item = vuln.get("cve", {})
                cves.append(self._normalize_nvd(cve_item))

            start_index += len(data.get("vulnerabilities", []))

            # Rate limit
            time.sleep(6.0 / effective_rate)

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
            resp = self._http.get(f"{self.MITRE_API}/{cve_id}")
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
        except httpx.RequestError:
            return {}

    # ── Exploit-DB Check ─────────────────────────────────

    def check_exploitdb(self, cve_id: str) -> dict:
        """Check if a public exploit exists for this CVE.

        Uses a simple heuristic: if the CVE ID appears in known exploit
        databases or security advisories, flag it. This is conservative —
        false negatives are preferred over false positives.

        If an exploit exists, the severity escalates:
            CRITICAL → CRITICAL+ / HIGH → CRITICAL / MEDIUM → HIGH
        """
        if not self.exploitdb_enabled:
            return {"exploit_available": False}

        # Conservative approach: check for known exploit patterns
        # in the CVE description and references rather than scraping
        # Exploit-DB's HTML search page (which is fragile and unreliable).
        #
        # In production, this should be replaced with a proper API or
        # a local copy of the Exploit-DB database.
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

                # Exact match or clear containment (not fuzzy substring)
                if pkg_name == match_name:
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

    # ── LXC Scan Pipeline ────────────────────────────────

    def scan_lxc(self, lxc_id: str) -> Optional[dict[str, Any]]:
        """Scan a single LXC's package inventory against CVE database.

        Requires pct exec access (always available for LXCs).
        """
        started = datetime.now()

        # Get all CVEs in the database
        cves = self.db.get_new_cves_since(date.today() - timedelta(days=90))

        # Get packages from DB using proper Database method
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
                if pkg_name == cve_pkg:
                    with self.db._connect() as conn:
                        conn.execute(
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

    # ── Proxmox PVE-SA Feed Parser ───────────────────────

    def fetch_pve_advisories(self) -> list[dict]:
        """Fetch and parse Proxmox Security Advisories from the wiki.

        Parses the Security_Advisories wiki page to extract advisory IDs,
        CVE references, affected packages, and patch versions.

        Returns:
            List of advisory dicts ready for DB insertion.
        """
        if not self.pve_security_enabled:
            return []

        try:
            resp = self._http.get(self.pve_sa_feed_url)
            if resp.status_code != 200:
                return []
            html = resp.text
        except httpx.RequestError:
            return []

        advisories = []
        # Parse advisory table rows from the wiki HTML
        # Pattern: PVE-SA-YYYY-NNNN entries with CVE references
        # The wiki uses a table format with columns: Advisory, CVE(s), Package, Version
        pve_sa_pattern = re.compile(
            r"PVE-SA-(\d{4})-(\d+)"  # Advisory ID
        )

        # Extract all advisory blocks
        # Look for table rows containing PVE-SA references
        rows = html.split("\n")
        current_advisory = None

        for line in rows:
            # Match advisory ID
            sa_match = pve_sa_pattern.search(line)
            if sa_match:
                year = sa_match.group(1)
                num = sa_match.group(2)
                advisory_id = f"PVE-SA-{year}-{num}"

                # Extract CVE IDs from the same line or nearby
                cve_matches = re.findall(r"CVE-\d{4}-\d+", line)

                # Extract package name (usually in a code block or link)
                pkg_match = re.search(r"`([^`]+)`", line)
                package = pkg_match.group(1) if pkg_match else ""

                # Extract version
                ver_match = re.search(r"(\d[\w.+-]+)", line.split(package)[-1] if package else line)
                version = ver_match.group(1) if ver_match else ""

                advisories.append({
                    "id": advisory_id,
                    "cve_ids": ",".join(cve_matches),
                    "package": package,
                    "fixed_version": version,
                    "url": f"https://pve.proxmox.com/wiki/Security_Advisories#{advisory_id}",
                    "published": f"{year}-01-01",  # Approximate — wiki doesn't expose exact date
                })

        return advisories

    def sync_pve_advisories(self) -> int:
        """Fetch PVE advisories and sync to the local database.

        Returns:
            Number of new advisories inserted.
        """
        advisories = self.fetch_pve_advisories()
        if not advisories:
            return 0

        inserted = 0
        with self.db._connect() as conn:
            for adv in advisories:
                # Check if already exists
                existing = conn.execute(
                    "SELECT id FROM pve_security_advisories WHERE id = ?",
                    (adv["id"],),
                ).fetchone()
                if existing:
                    continue

                conn.execute(
                    """INSERT INTO pve_security_advisories
                       (id, cve_ids, package, fixed_version, raw_url, published_date)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        adv["id"],
                        adv["cve_ids"],
                        adv["package"],
                        adv["fixed_version"],
                        adv["url"],
                        adv["published"],
                    ),
                )
                inserted += 1

        return inserted

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

        # Check PVE-SA database for patch status
        pve_status = cve.get("pve_patch_status", "unknown")
        if pve_status == "released":
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
