"""Tests for system snapshot caching."""

import json
from datetime import datetime, timezone

import pytest

from src.database import Database


class TestSystemSnapshotCache:
    def test_cache_and_retrieve_snapshot(self, tmp_path):
        """Basic cache and retrieve round-trip."""
        db = Database(tmp_path / "test.db")
        db.cache_snapshot("repos", {"standard_repos": [{"name": "Enterprise", "enabled": False}]})

        result = db.get_snapshot("repos")
        assert result is not None
        assert result["data"]["standard_repos"][0]["name"] == "Enterprise"
        assert result["data"]["standard_repos"][0]["enabled"] is False
        assert result["updated_at"] is not None

    def test_get_missing_snapshot_returns_none(self, tmp_path):
        """get_snapshot returns None for uncached type."""
        db = Database(tmp_path / "test.db")
        assert db.get_snapshot("services") is None

    def test_cache_overwrites_previous(self, tmp_path):
        """Caching the same type twice updates the data."""
        db = Database(tmp_path / "test.db")
        db.cache_snapshot("health", {"cpu_pct": 10.0})
        db.cache_snapshot("health", {"cpu_pct": 50.0})

        result = db.get_snapshot("health")
        assert result["data"]["cpu_pct"] == 50.0

    def test_get_all_snapshots(self, tmp_path):
        """get_all_snapshots returns all cached types."""
        db = Database(tmp_path / "test.db")
        db.cache_snapshot("repos", {"repos": True})
        db.cache_snapshot("health", {"health": True})

        all_snaps = db.get_all_snapshots()
        assert "repos" in all_snaps
        assert "health" in all_snaps
        assert all_snaps["repos"]["data"]["repos"] is True
        assert all_snaps["health"]["data"]["health"] is True

    def test_clear_snapshots(self, tmp_path):
        """clear_snapshots removes all cached data."""
        db = Database(tmp_path / "test.db")
        db.cache_snapshot("repos", {"repos": True})
        db.cache_snapshot("health", {"health": True})
        db.clear_snapshots()

        assert db.get_snapshot("repos") is None
        assert db.get_snapshot("health") is None

    def test_snapshot_stores_complex_data(self, tmp_path):
        """Snapshot handles nested dicts and lists."""
        db = Database(tmp_path / "test.db")
        data = {
            "services": [
                {"name": "pveproxy", "state": "running"},
                {"name": "corosync", "state": "dead"},
            ],
            "node": "pve1",
        }
        db.cache_snapshot("services", data)

        result = db.get_snapshot("services")
        assert len(result["data"]["services"]) == 2
        assert result["data"]["node"] == "pve1"

    def test_updated_at_is_recent(self, tmp_path):
        """updated_at reflects the cache time."""
        db = Database(tmp_path / "test.db")
        db.cache_snapshot("health", {"cpu_pct": 5.0})
        result = db.get_snapshot("health")

        # Should be within 60 seconds of now
        cached = datetime.fromisoformat(result["updated_at"])
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        delta = abs((now - cached).total_seconds())
        assert delta < 60
