"""Version info with build timestamp.

Reads the version from pyproject.toml and appends a build timestamp
so operators can verify they're running the latest build.
"""

import os
from datetime import UTC, datetime

# Static version from pyproject.toml — update on each release
VERSION = "0.5.0"

# Build timestamp — set at deploy/sync time
BUILD_TS_FILE = os.path.join(os.path.dirname(__file__), ".build_ts")


def _read_build_ts() -> str:
    """Read build timestamp from file, or return 'unknown'."""
    try:
        with open(BUILD_TS_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except (FileNotFoundError, OSError):
        return "unknown"


def version_string() -> str:
    """Return version with build timestamp, e.g. '0.5.0 (2026-05-05T14:32:00Z)'."""
    ts = _read_build_ts()
    return f"{VERSION} ({ts})"


def write_build_ts() -> None:
    """Write current UTC timestamp to the build timestamp file."""
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(BUILD_TS_FILE, "w", encoding="utf-8") as f:
        f.write(ts)
