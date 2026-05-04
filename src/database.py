"""SQLite database layer for pve-sentinel."""

import sqlite3
from datetime import date
from pathlib import Path
from typing import Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    published DATE,
    modified DATE,
    affected_package TEXT,
    fixed_version TEXT,
    exploit_available INTEGER DEFAULT 0,
    exploit_db_id TEXT,
    exploit_type TEXT,
    exploit_verified INTEGER,
    exploit_auth_required INTEGER,
    mitre_references TEXT,
    sentinel_priority TEXT,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS host_packages (
    name TEXT,
    version TEXT,
    architecture TEXT DEFAULT '',
    last_seen DATE,
    PRIMARY KEY (name, version)
);

CREATE TABLE IF NOT EXISTS lxc_packages (
    lxc_id TEXT,
    package_name TEXT,
    version TEXT,
    architecture TEXT DEFAULT '',
    last_seen DATE,
    PRIMARY KEY (lxc_id, package_name, architecture)
);

CREATE TABLE IF NOT EXISTS cve_matches (
    cve_id TEXT REFERENCES cves(id),
    package_name TEXT,
    installed_version TEXT,
    upstream_fixed_version TEXT,
    pve_patch_status TEXT DEFAULT 'unknown',
    pve_advisory_id TEXT,
    pve_advisory_url TEXT,
    impact_assessment TEXT,
    exposure_level TEXT DEFAULT 'UNKNOWN',
    mitigation_steps TEXT,
    patched_at DATE,
    detected_at DATE DEFAULT CURRENT_DATE,
    PRIMARY KEY (cve_id, package_name)
);

CREATE TABLE IF NOT EXISTS lxc_cve_matches (
    lxc_id TEXT,
    cve_id TEXT REFERENCES cves(id),
    package_name TEXT,
    installed_version TEXT,
    detected_at DATE DEFAULT CURRENT_DATE,
    PRIMARY KEY (lxc_id, cve_id, package_name)
);

CREATE TABLE IF NOT EXISTS pve_security_advisories (
    id TEXT PRIMARY KEY,
    published DATE,
    cve_ids TEXT,
    affected_packages TEXT,
    patched_versions TEXT,
    raw_url TEXT
);

CREATE TABLE IF NOT EXISTS scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    new_cves_found INTEGER DEFAULT 0,
    packages_checked INTEGER DEFAULT 0,
    duration_seconds REAL
);

CREATE TABLE IF NOT EXISTS guests (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT,
    status TEXT,
    os_type TEXT,
    os_version TEXT,
    package_manager TEXT,
    qemu_agent INTEGER DEFAULT 0,
    last_scanned TIMESTAMP,
    error TEXT
);

CREATE TABLE IF NOT EXISTS guest_packages (
    guest_id TEXT REFERENCES guests(id),
    package_name TEXT,
    version TEXT,
    architecture TEXT DEFAULT '',
    source_package TEXT,
    source_type TEXT DEFAULT 'system',
    last_seen DATE,
    PRIMARY KEY (guest_id, package_name, architecture, source_type)
);

CREATE TABLE IF NOT EXISTS guest_cve_matches (
    guest_id TEXT REFERENCES guests(id),
    cve_id TEXT REFERENCES cves(id),
    package_name TEXT,
    installed_version TEXT,
    vulnerable INTEGER DEFAULT 1,
    network_facing INTEGER DEFAULT 0,
    exposure_level TEXT DEFAULT 'UNKNOWN',
    detected_at DATE DEFAULT CURRENT_DATE,
    PRIMARY KEY (guest_id, cve_id, package_name)
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_package ON cves(affected_package);
CREATE INDEX IF NOT EXISTS idx_cve_matches_pkg ON cve_matches(package_name);
CREATE INDEX IF NOT EXISTS idx_cve_matches_detected ON cve_matches(detected_at);
CREATE INDEX IF NOT EXISTS idx_lxc_matches_lxc ON lxc_cve_matches(lxc_id);
CREATE INDEX IF NOT EXISTS idx_guest_matches_guest ON guest_cve_matches(guest_id);
CREATE INDEX IF NOT EXISTS idx_guest_packages_guest ON guest_packages(guest_id);
CREATE INDEX IF NOT EXISTS idx_scan_log_date ON scan_log(started_at);
"""


class Database:
    """SQLite database manager for pve-sentinel."""

    def __init__(self, db_path: str | Path = "sentinel.db"):
        self.db_path = Path(db_path)
        # CIS L1: restrict directory permissions to owner only
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema if not exists."""
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """Get a database connection with WAL mode and foreign keys enabled."""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    # ── CVE operations ────────────────────────────────────

    def insert_cve(self, cve_data: dict) -> None:
        """Insert or update a CVE record."""
        cve_id = cve_data.get("id")
        if not cve_id:
            raise ValueError("CVE data missing required 'id' field")

        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cves
                   (id, description, severity, cvss_score, published, modified,
                    affected_package, fixed_version, exploit_available,
                    exploit_db_id, exploit_type, exploit_verified,
                    exploit_auth_required, mitre_references, sentinel_priority,
                    raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id,
                    cve_data.get("description", ""),
                    cve_data.get("severity", ""),
                    cve_data.get("cvss_score"),
                    cve_data.get("published"),
                    cve_data.get("modified"),
                    cve_data.get("affected_package", ""),
                    cve_data.get("fixed_version", ""),
                    int(cve_data.get("exploit_available", False)),
                    cve_data.get("exploit_db_id", ""),
                    cve_data.get("exploit_type", ""),
                    int(cve_data.get("exploit_verified", False)),
                    int(cve_data.get("exploit_auth_required", False)),
                    cve_data.get("mitre_references", ""),
                    cve_data.get("sentinel_priority", ""),
                    cve_data.get("raw_json", ""),
                ),
            )

    def get_cves_by_severity(self, severity: str, limit: int = 100) -> list[dict]:
        """Get CVEs filtered by severity."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cves WHERE severity = ? ORDER BY cvss_score DESC LIMIT ?",
                (severity, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_cves_for_package(self, package: str) -> list[dict]:
        """Get CVEs affecting a specific package."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cves WHERE affected_package = ?",
                (package,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_new_cves_since(self, since_date: date) -> list[dict]:
        """Get CVEs detected since a given date."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cves WHERE date(published) >= ? ORDER BY cvss_score DESC",
                (since_date.isoformat(),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Package operations ────────────────────────────────

    def update_host_packages(self, packages: list[dict]) -> None:
        """Replace the host package inventory."""
        with self._connect() as conn:
            conn.execute("DELETE FROM host_packages")
            conn.executemany(
                "INSERT INTO host_packages (name, version, architecture, last_seen) "
                "VALUES (?, ?, ?, date('now'))",
                [(p["name"], p["version"], p.get("architecture", "")) for p in packages],
            )

    def update_lxc_packages(self, lxc_id: str, packages: list[dict]) -> None:
        """Replace package inventory for a specific LXC."""
        with self._connect() as conn:
            conn.execute("DELETE FROM lxc_packages WHERE lxc_id = ?", (lxc_id,))
            conn.executemany(
                "INSERT INTO lxc_packages (lxc_id, package_name, version, architecture, last_seen) "
                "VALUES (?, ?, ?, ?, date('now'))",
                [(lxc_id, p["name"], p["version"], p.get("architecture", "")) for p in packages],
            )

    def get_host_packages(self) -> list[dict]:
        """Get current host package inventory."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM host_packages").fetchall()
        return [dict(r) for r in rows]

    # ── CVE match operations ──────────────────────────────

    def insert_cve_match(self, match: dict) -> None:
        """Insert a host-level CVE match."""
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cve_matches
                   (cve_id, package_name, installed_version, upstream_fixed_version,
                    pve_patch_status, pve_advisory_id, pve_advisory_url,
                    impact_assessment, exposure_level, mitigation_steps, patched_at,
                    detected_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, date('now'))""",
                (
                    match["cve_id"],
                    match["package_name"],
                    match.get("installed_version", ""),
                    match.get("upstream_fixed_version", ""),
                    match.get("pve_patch_status", "unknown"),
                    match.get("pve_advisory_id", ""),
                    match.get("pve_advisory_url", ""),
                    match.get("impact_assessment", ""),
                    match.get("exposure_level", "UNKNOWN"),
                    match.get("mitigation_steps", ""),
                    match.get("patched_at"),
                ),
            )

    def get_unpatched_matches(self) -> list[dict]:
        """Get CVE matches where Proxmox patch is pending."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_matches WHERE pve_patch_status = 'pending' "
                "ORDER BY exposure_level"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_matches_by_exposure(self, level: str) -> list[dict]:
        """Get CVE matches by exposure level."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_matches WHERE exposure_level = ?",
                (level,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Scan log operations ───────────────────────────────

    def log_scan(
        self,
        scan_type: str,
        new_cves: int = 0,
        packages: int = 0,
        duration: float = 0,
    ) -> None:
        """Record a scan completion."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_log (scan_type, completed_at, new_cves_found, "
                "packages_checked, duration_seconds) "
                "VALUES (?, datetime('now'), ?, ?, ?)",
                (scan_type, new_cves, packages, duration),
            )

    def get_last_scan_date(self, scan_type: str = "host") -> Optional[date]:
        """Get the date of the last completed scan."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT date(completed_at) as d FROM scan_log "
                "WHERE scan_type = ? AND completed_at IS NOT NULL "
                "ORDER BY completed_at DESC LIMIT 1",
                (scan_type,),
            ).fetchone()
        if row and row["d"]:
            return date.fromisoformat(row["d"])
        return None

    # ── Config operations ─────────────────────────────────

    def get_config(self, key: str, default: str = "") -> str:
        """Get a config value."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM config WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_config(self, key: str, value: str) -> None:
        """Set a config value."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                (key, value),
            )
