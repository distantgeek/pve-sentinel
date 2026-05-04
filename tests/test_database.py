"""Tests for pve-sentinel database layer."""

import tempfile
from pathlib import Path

import pytest

from src.database import Database


@pytest.fixture
def db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = Database(db_path)
    yield db
    Path(db_path).unlink(missing_ok=True)


class TestDatabase:
    def test_init_creates_tables(self, db):
        """Database initialization should create all tables."""
        with db._connect() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        table_names = [t["name"] for t in tables]
        assert "cves" in table_names
        assert "host_packages" in table_names
        assert "cve_matches" in table_names
        assert "scan_log" in table_names

    def test_insert_and_get_cve(self, db):
        """Should insert and retrieve CVE records."""
        db.insert_cve({
            "id": "CVE-2026-TEST1",
            "description": "Test CVE",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "published": "2026-05-01",
            "modified": "2026-05-02",
            "affected_package": "test-package",
            "fixed_version": "1.2.3",
        })

        cves = db.get_cves_for_package("test-package")
        assert len(cves) == 1
        assert cves[0]["id"] == "CVE-2026-TEST1"
        assert cves[0]["severity"] == "HIGH"

    def test_get_cves_by_severity(self, db):
        """Should filter CVEs by severity."""
        db.insert_cve({
            "id": "CVE-2026-HIGH1",
            "description": "High CVE",
            "severity": "HIGH",
            "cvss_score": 8.0,
        })
        db.insert_cve({
            "id": "CVE-2026-MED1",
            "description": "Medium CVE",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
        })

        high_cves = db.get_cves_by_severity("HIGH")
        assert len(high_cves) == 1
        assert high_cves[0]["id"] == "CVE-2026-HIGH1"

    def test_host_packages_crud(self, db):
        """Should update and retrieve host packages."""
        packages = [
            {"name": "nginx", "version": "1.24.0", "architecture": "amd64"},
            {"name": "openssl", "version": "3.0.15", "architecture": "amd64"},
        ]
        db.update_host_packages(packages)

        result = db.get_host_packages()
        assert len(result) == 2
        assert result[0]["name"] == "nginx"

    def test_insert_cve_match(self, db):
        """Should insert and query CVE matches."""
        # Must insert the referenced CVE first (foreign key)
        db.insert_cve({
            "id": "CVE-2026-TEST1",
            "description": "Test CVE",
            "severity": "HIGH",
            "cvss_score": 7.5,
        })
        db.insert_cve_match({
            "cve_id": "CVE-2026-TEST1",
            "package_name": "nginx",
            "installed_version": "1.24.0",
            "upstream_fixed_version": "1.24.1",
            "pve_patch_status": "pending",
            "exposure_level": "HIGH",
        })

        unpatched = db.get_unpatched_matches()
        assert len(unpatched) == 1
        assert unpatched[0]["package_name"] == "nginx"
        assert unpatched[0]["pve_patch_status"] == "pending"

    def test_scan_log(self, db):
        """Should log and query scan history."""
        db.log_scan("host", new_cves=5, packages=100, duration=12.5)
        db.log_scan("host", new_cves=2, packages=100, duration=8.0)

        last = db.get_last_scan_date("host")
        assert last is not None

    def test_config_persistence(self, db):
        """Should get/set config values."""
        db.set_config("last_nvd_sync", "2026-05-04T12:00:00Z")
        assert db.get_config("last_nvd_sync") == "2026-05-04T12:00:00Z"

    def test_config_default(self, db):
        """Should return default for unset config keys."""
        assert db.get_config("nonexistent", "fallback") == "fallback"
