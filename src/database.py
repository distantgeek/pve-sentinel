"""SQLite database layer for pve-sentinel."""

import sqlite3
from datetime import date
from pathlib import Path
from typing import ClassVar

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

CREATE TABLE IF NOT EXISTS system_snapshot (
    type TEXT PRIMARY KEY,
    data TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS conversation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    topic TEXT
);

CREATE TABLE IF NOT EXISTS cve_archive (
    id TEXT PRIMARY KEY,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    published DATE,
    modified DATE,
    affected_package TEXT,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    archive_reason TEXT
);

CREATE TABLE IF NOT EXISTS conversation_archive (
    id INTEGER PRIMARY KEY,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP,
    topic TEXT,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_package ON cves(affected_package);
CREATE INDEX IF NOT EXISTS idx_cve_matches_pkg ON cve_matches(package_name);
CREATE INDEX IF NOT EXISTS idx_cve_matches_detected ON cve_matches(detected_at);
CREATE INDEX IF NOT EXISTS idx_lxc_matches_lxc ON lxc_cve_matches(lxc_id);
CREATE INDEX IF NOT EXISTS idx_guest_matches_guest ON guest_cve_matches(guest_id);
CREATE INDEX IF NOT EXISTS idx_guest_packages_guest ON guest_packages(guest_id);
CREATE INDEX IF NOT EXISTS idx_scan_log_date ON scan_log(started_at);
CREATE INDEX IF NOT EXISTS idx_conversation_role ON conversation_log(role);
CREATE INDEX IF NOT EXISTS idx_conversation_topic ON conversation_log(topic);
CREATE INDEX IF NOT EXISTS idx_conversation_ts ON conversation_log(timestamp);
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
            # Deduplicate by (name, version) to handle API returning duplicates
            seen = set()
            unique = []
            for p in packages:
                key = (p["name"], p["version"])
                if key not in seen:
                    seen.add(key)
                    unique.append((p["name"], p["version"], p.get("architecture", "")))
            conn.executemany(
                "INSERT INTO host_packages (name, version, architecture, last_seen) "
                "VALUES (?, ?, ?, date('now'))",
                unique,
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

    def get_last_scan_date(self, scan_type: str = "host") -> date | None:
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

    # ── System snapshot operations ─────────────────────────

    def cache_snapshot(self, snap_type: str, data: dict) -> None:
        """Cache a system snapshot (repos, health, services) as JSON."""
        import json
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_snapshot (type, data, updated_at) "
                "VALUES (?, ?, datetime('now'))",
                (snap_type, json.dumps(data)),
            )

    def get_snapshot(self, snap_type: str) -> dict | None:
        """Get a cached system snapshot, or None if not found."""
        import json
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data, updated_at FROM system_snapshot WHERE type = ?",
                (snap_type,),
            ).fetchone()
        if not row:
            return None
        return {
            "data": json.loads(row["data"]),
            "updated_at": row["updated_at"],
        }

    def get_all_snapshots(self) -> dict[str, dict]:
        """Get all cached snapshots keyed by type."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT type, data, updated_at FROM system_snapshot"
            ).fetchall()
        import json
        result = {}
        for row in rows:
            result[row["type"]] = {
                "data": json.loads(row["data"]),
                "updated_at": row["updated_at"],
            }
        return result

    def clear_snapshots(self) -> None:
        """Clear all cached snapshots."""
        with self._connect() as conn:
            conn.execute("DELETE FROM system_snapshot")

    # ── Database maintenance ────────────────────────────────

    def get_size_mb(self) -> float:
        """Get current database file size in MB."""
        try:
            return self.db_path.stat().st_size / (1024 * 1024)
        except OSError:
            return 0.0

    def get_maintenance_status(self) -> dict:
        """Get database maintenance status with tiered level."""
        size = self.get_size_mb()
        if size < 50:
            level = "ok"
        elif size < 75:
            level = "info"
        elif size < 100:
            level = "warning"
        else:
            level = "critical"

        with self._connect() as conn:
            counts = {
                "cves": conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
                "matches": conn.execute("SELECT COUNT(*) FROM cve_matches").fetchone()[0],
                "advisories": conn.execute("SELECT COUNT(*) FROM pve_security_advisories").fetchone()[0],
                "snapshots": conn.execute("SELECT COUNT(*) FROM system_snapshot").fetchone()[0],
                "conversations": conn.execute("SELECT COUNT(*) FROM conversation_log").fetchone()[0],
                "archived_cves": conn.execute("SELECT COUNT(*) FROM cve_archive").fetchone()[0],
            }

        return {
            "size_mb": round(size, 2),
            "level": level,
            "row_counts": counts,
        }

    def vacuum(self) -> float:
        """Run VACUUM to reclaim space. Returns new size in MB."""
        with self._connect() as conn:
            conn.execute("VACUUM")
        return self.get_size_mb()

    def prune_old_cves(self, days: int = 365) -> int:
        """Archive and remove unmatched CVEs older than N days.

        Archives to cve_archive table before deletion for safety.
        Only affects CVEs with no active matches in cve_matches.
        Does not affect future detection — NVD fetch is independent.

        Returns:
            Number of CVEs archived and removed.
        """
        with self._connect() as conn:
            # Archive first
            conn.execute(
                "INSERT OR IGNORE INTO cve_archive "
                "(id, description, severity, cvss_score, published, modified, "
                "affected_package, archive_reason) "
                "SELECT id, description, severity, cvss_score, published, modified, "
                "affected_package, 'pruned_unmatched_' || ? || 'days' "
                "FROM cves WHERE id NOT IN "
                "(SELECT DISTINCT cve_id FROM cve_matches) "
                "AND date(modified) < date('now', ?)",
                (days, f"-{days} days"),
            )
            # Then delete
            result = conn.execute(
                "DELETE FROM cves WHERE id IN "
                "(SELECT id FROM cve_archive WHERE archive_reason = ?)",
                (f"pruned_unmatched_{days}days",),
            )
            return result.rowcount

    # ── Conversation log ────────────────────────────────────

    CONVERSATION_TOPICS: ClassVar[dict[str, list[str]]] = {
        "repositories": ["repo", "apt", "sources", "bookworm", "trixie", "subscription"],
        "cves": ["cve", "vuln", "patch", "update", "upgrade", "advisory"],
        "guests": ["vm", "lxc", "container", "guest", "pct", "qemu"],
        "health": ["health", "cpu", "ram", "disk", "storage", "temperature", "memory"],
        "network": ["network", "firewall", "bridge", "vlan", "dns", "ip", "subnet"],
        "security": ["security", "harden", "audit", "compliance", "guardrail"],
    }

    @classmethod
    def extract_topic(cls, text: str) -> str:
        """Extract topic from user input via keyword matching."""
        lower = text.lower()
        for topic, keywords in cls.CONVERSATION_TOPICS.items():
            for kw in keywords:
                if kw in lower:
                    return topic
        return "general"

    def log_conversation(self, role: str, content: str, topic: str = "") -> None:
        """Append a message to the conversation log."""
        if not topic:
            topic = self.extract_topic(content) if role == "user" else "assistant"
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO conversation_log (role, content, topic) VALUES (?, ?, ?)",
                (role, content, topic),
            )

    def get_recent_conversations(self, limit: int = 20) -> list[dict]:
        """Get the most recent conversation entries."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, role, content, timestamp, topic FROM conversation_log "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def get_conversations_by_topic(self, topic: str, limit: int = 10) -> list[dict]:
        """Get recent conversations matching a topic."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, role, content, timestamp, topic FROM conversation_log "
                "WHERE topic = ? ORDER BY id DESC LIMIT ?",
                (topic, limit),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def prune_conversations(self, days: int = 90) -> int:
        """Archive and remove conversations older than N days."""
        with self._connect() as conn:
            # Archive
            conn.execute(
                "INSERT INTO conversation_archive (role, content, timestamp, topic) "
                "SELECT role, content, timestamp, topic FROM conversation_log "
                "WHERE date(timestamp) < date('now', ?)",
                (f"-{days} days",),
            )
            # Delete
            result = conn.execute(
                "DELETE FROM conversation_log WHERE date(timestamp) < date('now', ?)",
                (f"-{days} days",),
            )
            return result.rowcount
