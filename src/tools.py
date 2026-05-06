"""Tool registry for pve-sentinel.

Defines available tools that the LLM can request during conversation.
Each tool has a name, purpose, access level, and execution function.
"""

import json
from typing import Any, Optional

# ── Tool definitions ────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, dict[str, str]] = {
    "proxmox_api": {
        "purpose": "Query Proxmox VE API (read-only GET requests)",
        "access": "Auto-approved for GET; write/destructive blocked",
        "format": "[TOOL:proxmox_api] GET /nodes/{node}/path",
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


# ── Tool execution ──────────────────────────────────────────────────


def execute_proxmox_api(
    method: str, path: str, proxmox: Any
) -> dict[str, Any]:
    """Execute a Proxmox API call via proxmoxer.

    Args:
        method: HTTP method (GET only for tool use).
        path: API path (e.g., /nodes/kevbot-pve/apt/repositories).
        proxmox: ProxmoxTools instance.

    Returns:
        dict with 'success', 'data', 'error' keys.
    """
    if method.upper() != "GET":
        return {
            "success": False,
            "error": f"Only GET requests allowed via tool. Use /proxmox <action> for {method.upper()} operations.",
        }

    if not proxmox:
        return {
            "success": False,
            "error": "Proxmox API not configured.",
        }

    try:
        result = proxmox.run_command(path, method="get")
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
                "error": f"Invalid proxmox_api args. Expected: GET /path, got: {tool_args}",
            }
        method, path = parts
        return execute_proxmox_api(method, path, proxmox)

    return {"success": False, "error": f"Unknown tool: {tool_name}"}
