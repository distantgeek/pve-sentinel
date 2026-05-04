"""Tests for pve-sentinel CVE scanner."""

import pytest

from src.database import Database
from src.cve_scanner import CVEScanner


class TestCVEScanner:
    @pytest.fixture
    def scanner(self, tmp_path):
        db = Database(tmp_path / "test.db")
        # Disable external API calls for unit tests
        return CVEScanner(
            db,
            mitre_enabled=False,
            exploitdb_enabled=False,
            pve_security_enabled=False,
        )

    def test_compute_priority_critical_exploit(self, scanner):
        assert scanner.compute_priority("CRITICAL", True) == "CRITICAL+"

    def test_compute_priority_critical_no_exploit(self, scanner):
        assert scanner.compute_priority("CRITICAL", False) == "CRITICAL"

    def test_compute_priority_high_exploit(self, scanner):
        assert scanner.compute_priority("HIGH", True) == "CRITICAL"

    def test_compute_priority_high_no_exploit(self, scanner):
        assert scanner.compute_priority("HIGH", False) == "HIGH"

    def test_compute_priority_medium_exploit(self, scanner):
        assert scanner.compute_priority("MEDIUM", True) == "HIGH"

    def test_compute_priority_medium_no_exploit(self, scanner):
        assert scanner.compute_priority("MEDIUM", False) == "MEDIUM"

    def test_compute_priority_low_exploit(self, scanner):
        assert scanner.compute_priority("LOW", True) == "MEDIUM"

    def test_compute_priority_low_no_exploit(self, scanner):
        assert scanner.compute_priority("LOW", False) == "LOW"

    def test_compute_priority_unknown_exploit(self, scanner):
        """Even unknown severity should escalate with exploit."""
        assert scanner.compute_priority("", True) == "MEDIUM"

    def test_normalize_nvd_basic(self, scanner):
        """NVD CVE normalization should extract fields correctly."""
        cve_item = {
            "id": "CVE-2026-TEST1",
            "descriptions": [
                {"lang": "en", "value": "Test vulnerability"},
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }],
            },
            "published": "2026-05-01T00:00:00.000",
            "lastModified": "2026-05-02T00:00:00.000",
        }

        result = scanner._normalize_nvd(cve_item)
        assert result["id"] == "CVE-2026-TEST1"
        assert result["severity"] == "CRITICAL"
        assert result["cvss_score"] == 9.8
        assert result["description"] == "Test vulnerability"
