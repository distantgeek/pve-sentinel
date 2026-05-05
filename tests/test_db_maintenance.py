"""Tests for database maintenance and conversation log."""

import os
import time
from datetime import datetime, timezone

import pytest

from src.database import Database


class TestDatabaseMaintenance:
    def test_get_size_mb_returns_float(self, tmp_path):
        """get_size_mb returns a float representing file size."""
        db = Database(tmp_path / "test.db")
        size = db.get_size_mb()
        assert isinstance(size, float)
        assert size > 0  # Fresh DB has some size

    def test_maintenance_status_ok_under_50mb(self, tmp_path):
        """Status level is 'ok' for small databases."""
        db = Database(tmp_path / "test.db")
        status = db.get_maintenance_status()
        assert status["level"] == "ok"
        assert "size_mb" in status
        assert "row_counts" in status

    def test_maintenance_status_has_all_row_counts(self, tmp_path):
        """Row counts include all expected tables."""
        db = Database(tmp_path / "test.db")
        status = db.get_maintenance_status()
        counts = status["row_counts"]
        assert "cves" in counts
        assert "matches" in counts
        assert "advisories" in counts
        assert "snapshots" in counts
        assert "conversations" in counts
        assert "archived_cves" in counts

    def test_vacuum_reduces_size(self, tmp_path):
        """VACUUM completes without error and returns size."""
        db = Database(tmp_path / "test.db")
        # Insert some data to make vacuum meaningful
        for i in range(100):
            db.cache_snapshot(f"test_{i}", {"data": "x" * 1000})
        db.clear_snapshots()

        before = db.get_size_mb()
        after = db.vacuum()
        assert after <= before
        assert after > 0

    def test_prune_old_cves_removes_unmatched(self, tmp_path):
        """Pruning archives and removes old unmatched CVEs."""
        db = Database(tmp_path / "test.db")
        # Insert a CVE with no matches, old date
        db.insert_cve({
            "id": "CVE-2020-00001",
            "description": "Old unmatched CVE",
            "severity": "LOW",
            "cvss_score": 2.0,
            "published": "2020-01-01",
            "modified": "2020-01-01",
            "affected_package": "old-pkg",
        })
        # Insert a CVE with no matches, recent date
        db.insert_cve({
            "id": "CVE-2026-00001",
            "description": "Recent unmatched CVE",
            "severity": "HIGH",
            "cvss_score": 7.0,
            "published": "2026-01-01",
            "modified": "2026-01-01",
            "affected_package": "new-pkg",
        })

        count = db.prune_old_cves(days=365)
        assert count == 1  # Only the old one should be pruned

        # Verify it was archived
        archived = db.get_maintenance_status()["row_counts"]["archived_cves"]
        assert archived == 1

        # Verify recent one still exists
        cves = db.get_cves_by_severity("HIGH")
        assert len(cves) == 1
        assert cves[0]["id"] == "CVE-2026-00001"


class TestConversationLog:
    def test_log_and_retrieve_conversation(self, tmp_path):
        """Basic log and retrieve round-trip."""
        db = Database(tmp_path / "test.db")
        db.log_conversation("user", "What's the status of my repos?")
        db.log_conversation("assistant", "Your repos are configured.")

        recent = db.get_recent_conversations()
        assert len(recent) == 2
        assert recent[0]["role"] == "user"
        assert recent[1]["role"] == "assistant"

    def test_topic_extraction_repositories(self, tmp_path):
        """Topic extraction identifies repository-related queries."""
        assert Database.extract_topic("Are my apt repos configured?") == "repositories"
        assert Database.extract_topic("Bookworm repos are stale") == "repositories"
        assert Database.extract_topic("Check the sources list") == "repositories"

    def test_topic_extraction_cves(self, tmp_path):
        """Topic extraction identifies CVE-related queries."""
        assert Database.extract_topic("Any new CVEs today?") == "cves"
        assert Database.extract_topic("Patch the vulnerable package") == "cves"
        assert Database.extract_topic("Check the advisory feed") == "cves"

    def test_topic_extraction_health(self, tmp_path):
        """Topic extraction identifies health-related queries."""
        assert Database.extract_topic("What's the CPU usage?") == "health"
        assert Database.extract_topic("Check disk space") == "health"
        assert Database.extract_topic("Memory is running high") == "health"

    def test_topic_extraction_general(self, tmp_path):
        """Unmatched topics default to 'general'."""
        assert Database.extract_topic("Hello there") == "general"
        assert Database.extract_topic("Random question about nothing") == "general"

    def test_get_recent_conversations_respects_limit(self, tmp_path):
        """get_recent_conversations returns only the requested number."""
        db = Database(tmp_path / "test.db")
        for i in range(50):
            db.log_conversation("user", f"Message {i}")

        recent = db.get_recent_conversations(limit=5)
        assert len(recent) == 5
        # Should be the last 5, in order
        assert recent[-1]["content"] == "Message 49"

    def test_get_conversations_by_topic(self, tmp_path):
        """Topic-based retrieval works correctly."""
        db = Database(tmp_path / "test.db")
        db.log_conversation("user", "What's the CPU usage?")  # health
        db.log_conversation("user", "Any new CVEs?")  # cves
        db.log_conversation("user", "Check apt repos")  # repositories

        health_msgs = db.get_conversations_by_topic("health")
        assert len(health_msgs) == 1
        assert "CPU" in health_msgs[0]["content"]

        cve_msgs = db.get_conversations_by_topic("cves")
        assert len(cve_msgs) == 1
        assert "CVE" in cve_msgs[0]["content"]

    def test_prune_conversations_archives(self, tmp_path):
        """Pruning conversations archives them before deletion."""
        db = Database(tmp_path / "test.db")
        db.log_conversation("user", "Old message")
        # Manually set old timestamp
        with db._connect() as conn:
            conn.execute(
                "UPDATE conversation_log SET timestamp = datetime('now', '-100 days') "
                "WHERE content = 'Old message'"
            )
        db.log_conversation("user", "Recent message")

        count = db.prune_conversations(days=90)
        assert count == 1

        # Verify recent message still exists
        recent = db.get_recent_conversations()
        assert len(recent) == 1
        assert recent[0]["content"] == "Recent message"
