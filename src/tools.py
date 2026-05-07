"""Tool registry for pve-sentinel.

Defines available tools that the LLM can request during conversation.
Supports single API calls and batch operations with inline confirmation.
"""

import json
from pathlib import Path
from typing import Any, Optional

# ── Constants ───────────────────────────────────────────────────────

BATCH_OPERATIONS_MAX = 5

BUILTIN_BLACKLIST = [
    "/stop", "/shutdown", "/reboot", "/reset",
    "/migrate", "/move", "/resize",
    "/acl", "/permissions", "/user", "/group",
    "/firewall",
]

DESTRUCTIVE_METHODS = {"DELETE"}

USER_BLACKLIST_PATH = Path.home() / ".config" / "pve-sentinel" / "blacklist.yaml"

# ── Tool definitions ────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, dict[str, str]] = {
    "proxmox_api": {
        "purpose": "Query Proxmox VE API (GET/POST/PUT/DELETE with confirmation)",
        "access": "GET auto-approved; write requires confirmation; DELETE requires typed confirm",
        "format": "[TOOL:proxmox_api] GET|POST|PUT|DELETE /nodes/{node}/path {body}",
    },
}


def get_tool_info() -> str:
    """Return formatted tool info for injection into LLM prompts."""
    lines = ["Available tools:"]
    for name, info in TOOL_REGISTRY.items():
        lines.append(f"  [TOOL:{name}] {info['format']} — {info['purpose']}")
    lines.append("")
    lines.append(
        "When you need data, output the tool request. Python will execute it "
        "and pass results back to you as [TOOL_RESULT]. Analyze the results "
        "and respond to the user."
    )
    return "\n".join(lines)


# ── Blacklist management ───────────────────────────────────────────

def _load_user_blacklist() -> list[str]:
    """Load user blacklist from YAML file."""
    if not USER_BLACKLIST_PATH.exists():
        return []
    try:
        import yaml
        with open(USER_BLACKLIST_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data.get("paths", []) if data else []
    except Exception:
        return []


def _save_user_blacklist(paths: list[str]) -> None:
    """Save user blacklist to YAML file."""
    USER_BLACKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    import yaml
    with open(USER_BLACKLIST_PATH, "w", encoding="utf-8") as f:
        yaml.dump({"paths": paths}, f, default_flow_style=False)


def get_full_blacklist() -> list[str]:
    """Merge built-in and user blacklists."""
    return BUILTIN_BLACKLIST + _load_user_blacklist()


def is_path_blacklisted(path: str) -> bool:
    """Check if path matches any blacklisted pattern."""
    return any(bl in path for bl in get_full_blacklist())


def add_to_user_blacklist(path: str) -> tuple[bool, str]:
    """Add a path to the user blacklist. Returns (success, message)."""
    full_list = get_full_blacklist()
    if path in full_list:
        return False, f"Path '{path}' is already blacklisted"
    user_list = _load_user_blacklist()
    user_list.append(path)
    _save_user_blacklist(user_list)
    return True, f"Added '{path}' to blacklist"


def remove_from_user_blacklist(path: str) -> tuple[bool, str]:
    """Remove a path from the user blacklist. Returns (success, message)."""
    if path in BUILTIN_BLACKLIST:
        return False, f"Path '{path}' is in the built-in blacklist and cannot be removed"
    user_list = _load_user_blacklist()
    if path not in user_list:
        return False, f"Path '{path}' is not in the user blacklist"
    user_list.remove(path)
    _save_user_blacklist(user_list)
    return True, f"Removed '{path}' from blacklist"


# ── Operation description ──────────────────────────────────────────

def describe_api_operation(method: str, path: str, body: dict = None) -> str:
    """Generate human-readable description of an API operation."""
    body = body or {}

    # VM operations
    if method == "POST" and "/qemu" in path:
        return (f"Create VM '{body.get('name', '?')}' (VMID {body.get('vmid', '?')})"
                f" — {body.get('cores', '?')}C/{body.get('memory', '?')}MB")
    elif method == "PUT" and "/qemu" in path and "/config" in path:
        return f"Modify VM {path.split('/')[-2]} config"
    elif method == "DELETE" and "/qemu" in path:
        return f"Delete VM {path.split('/')[-2]} — ⚠️ DESTRUCTIVE"

    # LXC operations
    elif method == "POST" and "/lxc" in path:
        return (f"Create LXC '{body.get('hostname', '?')}' (CTID {body.get('vmid', '?')})"
                f" — {body.get('cores', '?')}C/{body.get('memory', '?')}MB")
    elif method == "DELETE" and "/lxc" in path:
        return f"Delete LXC {path.split('/')[-2]} — ⚠️ DESTRUCTIVE"

    # Network operations
    elif method == "POST" and "/network" in path:
        return f"Create network interface '{body.get('iface', '?')}'"
    elif method == "PUT" and "/network" in path:
        return f"Modify network interface '{body.get('iface', '?')}'"
    elif method == "DELETE" and "/network" in path:
        return f"Delete network interface '{body.get('iface', '?')}' — ⚠️ DESTRUCTIVE"

    # Storage operations
    elif method == "POST" and "/storage" in path:
        return f"Create storage '{body.get('storage', '?')}'"
    elif method == "DELETE" and "/storage" in path:
        return f"Delete storage '{path.split('/')[-1]}' — ⚠️ DESTRUCTIVE"

    # Generic
    suffix = " — ⚠️ DESTRUCTIVE" if method in DESTRUCTIVE_METHODS else ""
    return f"{method} {path}{suffix}"


# ── Batch validation ───────────────────────────────────────────────

def validate_batch(operations: list) -> tuple[bool, str]:
    """Validate a batch of operations. Returns (valid, error_message)."""
    if not isinstance(operations, list):
        return False, "Batch must be a JSON array"
    if len(operations) > BATCH_OPERATIONS_MAX:
        return False, f"Batch exceeds maximum of {BATCH_OPERATIONS_MAX} operations"
    if len(operations) == 0:
        return False, "Batch must contain at least one operation"

    for i, op in enumerate(operations):
        method = op.get("method", "").upper()
        path = op.get("path", "")

        if is_path_blacklisted(path):
            return False, f"Operation {i+1} blocked: {path} is on the critical path blacklist"

        if method not in ("GET", "POST", "PUT", "DELETE"):
            return False, f"Operation {i+1} has invalid method: {method}"

    return True, ""


# ── Tool execution ──────────────────────────────────────────────────


def execute_proxmox_api(
    method: str, path: str, proxmox: Any, body: dict = None
) -> dict[str, Any]:
    """Execute a Proxmox API call via proxmoxer.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE).
        path: API path (e.g., /nodes/kevbot-pve/apt/repositories).
        proxmox: ProxmoxTools instance.
        body: Request body for POST/PUT operations.

    Returns:
        dict with 'success', 'data', 'error' keys.
    """
    if not proxmox:
        return {
            "success": False,
            "error": "Proxmox API not configured.",
        }

    try:
        result = proxmox.run_command(path, method=method.lower(), body=body)
        return {"success": True, "data": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


def execute_tool(
    tool_name: str, tool_args: str, proxmox: Any
) -> dict[str, Any]:
    """Route tool execution to the appropriate handler.

    Args:
        tool_name: Name of the tool (e.g., "proxmox_api").
        tool_args: Arguments for the tool (e.g., "GET /nodes/test/status").
        proxmox: ProxmoxTools instance.

    Returns:
        dict with 'success', 'data', 'error' keys.
    """
    if tool_name == "proxmox_api":
        parts = tool_args.split(None, 1)
        if len(parts) < 2:
            return {
                "success": False,
                "error": f"Invalid proxmox_api args. Expected: METHOD /path, got: {tool_args}",
            }
        method, rest = parts

        # Check for JSON body
        body = None
        try:
            body = json.loads(rest)
            # If it's a dict with method/path, extract them
            if isinstance(body, dict) and "method" in body and "path" in body:
                method = body["method"]
                rest = body["path"]
                body = body.get("body")
        except json.JSONDecodeError:
            pass

        return execute_proxmox_api(method, rest, proxmox, body)

    return {"success": False, "error": f"Unknown tool: {tool_name}"}
