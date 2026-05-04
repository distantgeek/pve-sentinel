"""Proxmox API wrapper for pve-sentinel.

Uses proxmoxer for API communication. All write operations pass through
the permission gate before execution.
"""

from typing import Any

from proxmoxer import ProxmoxAPI


class ProxmoxTools:
    """Read and (permission-gated) write operations on the Proxmox API."""

    def __init__(
        self,
        host: str,
        user: str,
        token_name: str,
        token_value: str,
        node: str = "",
        verify_ssl: bool = False,
    ):
        self.host = host
        self.node = node
        self.api = ProxmoxAPI(
            host,
            user=user,
            token_name=token_name,
            token_value=token_value,
            verify_ssl=verify_ssl,
        )

    def _get_node(self) -> str:
        """Auto-detect node name if not configured."""
        if self.node:
            return self.node
        nodes = self.api.nodes.get()
        if nodes:
            self.node = nodes[0]["node"]
            return self.node
        raise RuntimeError("No Proxmox nodes found")

    # ── Read operations ───────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Get high-level Proxmox status (node, VMs, LXCs, storage)."""
        node = self._get_node()
        status = self.api.nodes(node).status.get()
        vms = self.api.nodes(node).qemu.get()
        lxcs = self.api.nodes(node).lxc.get()
        storage = self.api.nodes(node).storage.get()

        return {
            "node": node,
            "status": status,
            "vms": [
                {
                    "vmid": v["vmid"],
                    "name": v.get("name", ""),
                    "status": v["status"],
                    "cpus": v.get("cpus"),
                    "maxmem": v.get("maxmem"),
                    "uptime": v.get("uptime"),
                }
                for v in vms
            ],
            "lxcs": [
                {
                    "vmid": c["vmid"],
                    "name": c.get("name", ""),
                    "status": c["status"],
                    "cpus": c.get("cpus"),
                    "maxmem": c.get("maxmem"),
                    "uptime": c.get("uptime"),
                }
                for c in lxcs
            ],
            "storage": storage,
        }

    def get_vm_status(self, vmid: int) -> dict[str, Any]:
        """Get detailed status for a specific VM."""
        node = self._get_node()
        return self.api.nodes(node).qemu(vmid).status.current.get()

    def get_lxc_status(self, vmid: int) -> dict[str, Any]:
        """Get detailed status for a specific LXC."""
        node = self._get_node()
        return self.api.nodes(node).lxc(vmid).status.current.get()

    def get_host_packages(self) -> list[dict[str, str]]:
        """Get installed packages and available updates on the Proxmox host.

        Uses pvesh to query apt update status.
        """
        import subprocess
        import json

        try:
            result = subprocess.run(
                ["pvesh", "get", f"/nodes/{self._get_node()}/apt/updates",
                 "--output-format", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                updates = json.loads(result.stdout)
                return [
                    {"name": u["Package"], "version": u.get("OldVersion", ""),
                     "architecture": u.get("Architecture", "")}
                    for u in updates
                ]
        except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError):
            pass
        return []

    def get_lxc_packages(self, lxc_id: int) -> list[dict[str, str]]:
        """Get installed packages inside an LXC via pct exec."""
        import subprocess
        import json

        # Detect OS type first
        try:
            os_check = subprocess.run(
                ["pct", "exec", str(lxc_id), "--", "cat", "/etc/os-release"],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            return []

        if os_check.returncode != 0:
            return []

        os_release = os_check.stdout.lower()

        # Determine package manager
        if "debian" in os_release or "ubuntu" in os_release:
            cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"]
        elif "fedora" in os_release or "centos" in os_release or "rhel" in os_release:
            cmd = ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"]
        elif "alpine" in os_release:
            cmd = ["apk", "info", "-v"]
        else:
            return []  # Unknown OS

        try:
            result = subprocess.run(
                ["pct", "exec", str(lxc_id), "--"] + cmd,
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                packages = []
                for line in result.stdout.strip().split("\n"):
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "architecture": parts[2] if len(parts) > 2 else "",
                        })
                return packages
        except subprocess.TimeoutExpired:
            pass
        return []

    # ── Write operations (must go through permission gate) ──

    def start_vm(self, vmid: int) -> dict:
        """Start a VM. Requires permission confirmation."""
        node = self._get_node()
        return self.api.nodes(node).qemu(vmid).status.start.post()

    def stop_vm(self, vmid: int) -> dict:
        """Stop a VM. Requires permission confirmation."""
        node = self._get_node()
        return self.api.nodes(node).qemu(vmid).status.stop.post()

    def start_lxc(self, vmid: int) -> dict:
        """Start an LXC. Requires permission confirmation."""
        node = self._get_node()
        return self.api.nodes(node).lxc(vmid).status.start.post()

    def stop_lxc(self, vmid: int) -> dict:
        """Stop an LXC. Requires permission confirmation."""
        node = self._get_node()
        return self.api.nodes(node).lxc(vmid).status.stop.post()

    def run_command(self, api_path: str, method: str = "get") -> dict:
        """Run an arbitrary Proxmox API command. Requires permission confirmation."""
        import subprocess
        import json

        cmd = ["pvesh", method, api_path, "--output-format", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout)
        raise RuntimeError(f"API command failed: {result.stderr}")
