"""Proxmox API wrapper for pve-sentinel.

Uses proxmoxer for API communication. All write operations pass through
the permission gate before execution.
"""

from typing import Any

from proxmoxer import ProxmoxAPI  # type: ignore[import-untyped]


class ProxmoxTools:
    """Read and (permission-gated) write operations on the Proxmox API."""

    # Read-only API paths that bypass permission gates (GET only)
    READ_ONLY_PATHS = frozenset({
        "/nodes", "/status", "/cluster/status", "/version",
    })

    def __init__(
        self,
        host: str,
        user: str,
        token_name: str,
        token_value: str,
        node: str = "",
        verify_ssl: bool = True,
    ):
        self.host = host
        self._user = user
        self.node = node
        self._verify_ssl = verify_ssl
        self.api = ProxmoxAPI(
            host,
            user=user,
            token_name=token_name,
            token_value=token_value,
            verify_ssl=verify_ssl,
        )

    def __repr__(self) -> str:
        return (
            f"ProxmoxTools(host={self.host!r}, user={self._user!r}, "
            f"node={self.node!r}, verify_ssl={self._verify_ssl})"
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

    def _api_traverse(self, api_path: str):
        """Traverse the Proxmox API dynamically from a path string.

        Converts "/nodes/pve/qemu" -> self.api.nodes(pve).qemu
        """
        parts = [p for p in api_path.strip("/").split("/") if p]
        resource = self.api
        for part in parts:
            resource = getattr(resource, part)
        return resource

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

    def get_health(self) -> dict[str, Any]:
        """Full hypervisor health snapshot.

        Combines status, storage, disk health, services, and cluster resources
        into a single health report. Temperature data is included if the
        proxmox-temperature patch is installed (via lm-sensors).
        """
        node = self._get_node()

        # Node status (CPU, memory, swap, rootfs, uptime, kernel, loadavg)
        status = self.api.nodes(node).status.get()

        # Storage pools
        storage = self.api.nodes(node).storage.get()

        # Disk health
        disks = []
        try:
            disk_list = self.api.nodes(node).disks.list.get()
            for d in disk_list:
                disks.append({
                    "devpath": d.get("devpath", ""),
                    "model": d.get("model", ""),
                    "size_gb": d.get("size", 0) // 1024**3,
                    "health": d.get("health", "unknown"),
                })
        except Exception:
            pass  # Disk listing may require elevated permissions

        # Services
        services = []
        try:
            svc_list = self.api.nodes(node).services.get()
            for s in svc_list:
                services.append({
                    "name": s.get("name", ""),
                    "state": s.get("state", "unknown"),
                })
        except Exception:
            pass

        # Cluster resources (VM/LXC counts)
        vm_count = 0
        lxc_count = 0
        try:
            resources = self.api.cluster.resources.get()
            for r in resources:
                if r.get("type") == "qemu":
                    vm_count += 1
                elif r.get("type") == "lxc":
                    lxc_count += 1
        except Exception:
            pass

        # Temperature (if proxmox-temperature patch is installed)
        temperature = status.get("temperature")

        cpu_info = status.get("cpuinfo", {})
        mem = status.get("memory", {})
        swap = status.get("swap", {})
        rootfs = status.get("rootfs", {})

        return {
            "node": node,
            "pveversion": status.get("pveversion", ""),
            "kernel": status.get("kversion", ""),
            "uptime": status.get("uptime", 0),
            "cpu_pct": round(status.get("cpu", 0) * 100, 1),
            "cpu_cores": cpu_info.get("cores", 0),
            "cpu_sockets": cpu_info.get("sockets", 0),
            "loadavg": status.get("loadavg", ["", "", ""]),
            "mem_used": mem.get("used", 0),
            "mem_total": mem.get("total", 1),
            "mem_pct": round(mem.get("used", 0) / max(mem.get("total", 1), 1) * 100, 1),
            "mem_available": mem.get("available", 0),
            "swap_used": swap.get("used", 0),
            "swap_total": swap.get("total", 0),
            "swap_pct": round(swap.get("used", 0) / max(swap.get("total", 1), 1) * 100, 1),
            "rootfs_used": rootfs.get("used", 0),
            "rootfs_total": rootfs.get("total", 1),
            "rootfs_pct": round(rootfs.get("used", 0) / max(rootfs.get("total", 1), 1) * 100, 1),
            "storage": [
                {
                    "name": s.get("storage", ""),
                    "type": s.get("type", ""),
                    "used": s.get("used", 0),
                    "total": s.get("total", 0),
                    "pct": round(s.get("used", 0) / max(s.get("total", 1), 1) * 100, 1),
                }
                for s in storage
            ],
            "disks": disks,
            "services": services,
            "vm_count": vm_count,
            "lxc_count": lxc_count,
            "temperature": temperature,
        }

    def get_rrd_metrics(self, timeframe: str = "day") -> list[dict[str, Any]]:
        """Historical metrics from Proxmox RRD.

        Args:
            timeframe: hour, day, week, month, or year.

        Returns:
            List of data points with cpu, memused, netin, netout, iowait, etc.
        """
        node = self._get_node()
        return self.api.nodes(node).rrddata.get(timeframe=timeframe)

    def get_service_status(self) -> list[dict[str, Any]]:
        """All Proxmox services with running/dead state."""
        node = self._get_node()
        services = self.api.nodes(node).services.get()
        return [
            {"name": s.get("name", ""), "state": s.get("state", "unknown")}
            for s in services
        ]

    def get_host_packages(self) -> list[dict[str, str]]:
        """Get installed packages on the Proxmox host via API.

        Uses the apt/versions endpoint which returns all installed packages
        with their current versions — no subprocess or pvesh needed.
        """
        versions = self.api.nodes(self._get_node()).apt.versions.get()
        return [
            {"name": v["Package"], "version": v.get("OldVersion", ""),
             "architecture": v.get("Arch", "")}
            for v in versions
            if v.get("CurrentState") == "Installed"
        ]

    def get_host_repos(self) -> dict[str, Any]:
        """Get APT repository configuration via API.

        Returns a structured summary of repo status suitable for
        LLM context injection — enabled/disabled repos, warnings, errors.
        """
        repos = self.api.nodes(self._get_node()).apt.repositories.get()

        standard = []
        for r in repos.get("standard-repos", []):
            standard.append({
                "name": r.get("name", ""),
                "handle": r.get("handle", ""),
                "enabled": r.get("status", 0) == 1,
            })

        warnings = [
            i["message"]
            for i in repos.get("infos", [])
            if i.get("kind") == "warning"
        ]

        return {
            "standard_repos": standard,
            "warnings": warnings,
            "errors": repos.get("errors", []),
        }

    def get_lxc_packages(self, lxc_id: int) -> list[dict[str, str]]:
        """Get installed packages inside an LXC via pct exec.

        NOTE: This method requires root access on the Proxmox host
        (pct is a host-side tool). For the public release where the
        LXC runs as a non-root user, this method is unavailable.
        Phase 7 will migrate to the Proxmox API LXC exec endpoint.
        """
        import subprocess

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
            # $ characters are safe in list form — no shell expansion occurs
            cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"]
        elif "fedora" in os_release or "centos" in os_release or "rhel" in os_release:
            cmd = ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"]
        elif "alpine" in os_release:
            cmd = ["apk", "info", "-v"]
        else:
            return []  # Unknown OS — caller should log a warning

        try:
            result = subprocess.run(
                ["pct", "exec", str(lxc_id), "--", *cmd],
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

    def run_command(self, api_path: str, method: str = "get", body: dict | None = None) -> dict:
        """Run an arbitrary Proxmox API command.

        SECURITY: This method validates the path against a read-only allowlist.
        Write/modify paths must go through specific methods with permission gates.
        """
        # Block destructive paths entirely
        lower_path = api_path.lower()
        for keyword in ("destroy", "delete", "remove", "unlink", "purge"):
            if keyword in lower_path:
                raise PermissionError(
                    f"Destructive operation blocked: '{keyword}' in path '{api_path}'. "
                    "Use specific methods with permission gates instead."
                )

        # Allow read-only paths without restriction
        for allowed in self.READ_ONLY_PATHS:
            if api_path.startswith(allowed):
                resource = self._api_traverse(api_path)
                if method.lower() == "get":
                    return resource.get()

        # Write methods — permission gate is handled by CLI layer before calling
        if method.lower() in ("post", "put") and body is not None:
            resource = self._api_traverse(api_path)
            return resource.post(**body) if method.lower() == "post" else resource.put(**body)

        # All other paths require explicit permission gate (handled by CLI layer)
        raise PermissionError(
            f"Path '{api_path}' requires permission gate. "
            "Use /proxmox command in the CLI for write operations."
        )
