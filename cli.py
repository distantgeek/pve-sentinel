#!/usr/bin/env python3
"""pve-sentinel — LLM-driven security advisory agent for Proxmox VE.

Interactive CLI with slash commands, LLM advisory chat, and permission-gated
Proxmox API operations.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.config import load_config
from src.database import Database
from src.guardrails import list_presets
from src.opencode_client import OpenCodeClient
from src.permission_gate import PermissionGate
from src.proxmox_tools import ProxmoxTools
from src.version import version_string

# ── Constants ──────────────────────────────────────────────────────

HISTORY_FILE = str(Path.home() / ".config" / "pve-sentinel" / "cli_history")

COMMANDS = {
    "/digest": "Run full CVE scan and LLM summary",
    "/cve check <pkg>": "Deep-dive a specific package",
    "/cve scan": "Run host-only CVE scan",
    "/health": "Full hypervisor health dashboard",
    "/health rrd [period]": "Historical metrics (hour/day/week/month/year)",
    "/health services": "Proxmox service status",
    "/status": "Proxmox resource overview",
    "/refresh [type]": "Update cached system context (repos/health/services/all)",
    "/proxmox <action>": "Proxmox API operation (write = confirm)",
    "/guardrails [preset]": "Show or switch security framework preset",
    "/history": "Recent scan history",
    "/help": "Command reference",
    "/quit": "Exit the shell",
}

SLASH_COMMANDS = [cmd.split()[0] for cmd in COMMANDS]

# ── Banner ─────────────────────────────────────────────────────────

BANNER = r"""
   ___ _   ______    _________  _____________  ________
  / _ \ | / / __/___/ __/ __/ |/ /_  __/  _/ |/ / __/ /
 / ___/ |/ / _//___/\ \/ _//    / / / _/ //    / _// /__
/_/   |___/___/   /___/___/_/|_/ /_/ /___/_/|_/___/____/
"""


def print_banner() -> None:
    """Print the pve-sentinel banner with version info."""
    console = Console()
    console.print(Text(BANNER, style="bold cyan"))
    console.print(f"  pve-sentinel v{version_string()} — LLM-driven security advisory agent")
    console.print()


def _ssl_error_panel(error: Exception) -> Panel:
    """Create a helpful panel for SSL certificate errors."""
    return Panel(
        "Your Proxmox host uses a self-signed certificate.\n\n"
        "Fix options:\n"
        "  1. [bold]uv run python -m src.setup cert[/bold] — install the Proxmox CA cert\n"
        "  2. Set [bold]verify_ssl: false[/bold] in config.yaml (homelab only)",
        title="SSL Certificate Verification Failed",
        border_style="red",
    )


# ── CLI Shell ──────────────────────────────────────────────────────

class SentinelShell:
    """Interactive REPL for pve-sentinel."""

    def __init__(self):
        self.console = Console()
        self.config = self._load_config()
        self.db = Database(self.config.get("storage", {}).get("db_path", "sentinel.db"))
        self.client = self._init_client()
        self.proxmox = self._init_proxmox()
        self.gate = self._init_gate()

        # History directory
        Path(HISTORY_FILE).parent.mkdir(parents=True, exist_ok=True)

        # Prompt toolkit session
        self.completer = WordCompleter(SLASH_COMMANDS, ignore_case=True)
        self.session = PromptSession(
            completer=self.completer,
            history=FileHistory(HISTORY_FILE),
            style=Style.from_dict({
                "prompt": "ansicyan bold",
            }),
        )

    def _load_config(self) -> dict:
        """Load configuration, falling back to defaults on error."""
        try:
            return load_config()
        except (FileNotFoundError, ValueError) as e:
            self.console.print(Panel(
                f"[yellow]Config warning:[/yellow] {e}\n"
                "Some features may be unavailable.",
                title="Configuration",
                border_style="yellow",
            ))
            return {
                "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
                "proxmox": {},
                "guardrails": {"enabled": True, "preset": "general"},
                "storage": {"db_path": "sentinel.db"},
            }

    def _init_client(self) -> Optional[OpenCodeClient]:
        """Initialize OpenCode Go client, or None if API key missing."""
        try:
            guard = self.config.get("guardrails", {})
            return OpenCodeClient(
                model=self.config.get("model", {}).get("model_id", "glm-5.1"),
                guardrail_preset=guard.get("preset") if guard.get("enabled") else None,
                guardrail_custom=guard.get("custom"),
            )
        except ValueError as e:
            self.console.print(Panel(
                f"[yellow]LLM unavailable:[/yellow] {e}\n"
                "Set OPENCODE_GO_API_KEY to enable advisory features.",
                title="OpenCode Go",
                border_style="yellow",
            ))
            return None

    def _init_proxmox(self) -> Optional[ProxmoxTools]:
        """Initialize Proxmox API client, or None if config incomplete."""
        pmx = self.config.get("proxmox", {})
        if not pmx.get("host") or not pmx.get("token_value"):
            return None
        try:
            return ProxmoxTools(
                host=pmx["host"],
                user=pmx.get("user", ""),
                token_name=pmx.get("token_name", ""),
                token_value=pmx["token_value"],
                node=pmx.get("node", ""),
                verify_ssl=pmx.get("verify_ssl", True),
            )
        except Exception as e:
            error_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in error_str or "SSL" in error_str:
                self.console.print(_ssl_error_panel(e))
            else:
                self.console.print(Panel(
                    f"[yellow]Proxmox unavailable:[/yellow] {e}",
                    title="Proxmox API",
                    border_style="yellow",
                ))
            return None

    def _init_gate(self) -> PermissionGate:
        """Initialize permission gate from config."""
        perms = self.config.get("permissions", {})
        return PermissionGate(
            allowed_write=set(perms.get("allowed_write_actions", [])),
            deny_always=set(perms.get("deny_always", [])),
        )

    def run(self) -> None:
        """Main REPL loop."""
        print_banner()
        self._print_startup_status()

        while True:
            try:
                user_input = self.session.prompt("sentinel> ").strip()
            except (KeyboardInterrupt, EOFError):
                self.console.print()
                self.console.print("[dim]Goodbye.[/dim]")
                break

            if not user_input:
                continue

            if user_input.startswith("/"):
                self._handle_command(user_input)
            else:
                self._handle_chat(user_input)

    def _print_startup_status(self) -> None:
        """Print initialization status."""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")

        table.add_row("LLM", "GLM-5.1" if self.client else "unavailable")
        table.add_row("Proxmox", "connected" if self.proxmox else "not configured")
        table.add_row("Database", str(self.db.db_path))

        guard = self.config.get("guardrails", {})
        preset = guard.get("preset", "general") if guard.get("enabled") else "disabled"
        table.add_row("Guardrails", preset)

        self.console.print(table)
        self.console.print()
        self.console.print("Type [bold]/help[/bold] for commands, or ask a question directly.")
        self.console.print()

    def _handle_command(self, command: str) -> None:
        """Route slash commands to handlers."""
        parts = command.split()
        cmd = parts[0].lower()

        handlers = {
            "/help": self._cmd_help,
            "/quit": self._cmd_quit,
            "/exit": self._cmd_quit,
            "/status": self._cmd_status,
            "/history": self._cmd_history,
            "/digest": self._cmd_digest,
            "/health": self._cmd_health,
            "/refresh": self._cmd_refresh,
            "/guardrails": self._cmd_guardrails,
            "/cve": self._cmd_cve,
            "/proxmox": self._cmd_proxmox,
        }

        handler = handlers.get(cmd)
        if handler:
            handler(parts)
        else:
            self.console.print(f"[red]Unknown command:[/red] {cmd}")
            self.console.print("Type [bold]/help[/bold] for available commands.")

    def _handle_chat(self, prompt: str) -> None:
        """Send free-text input to LLM and display response."""
        if not self.client:
            self.console.print(
                "[yellow]LLM is not available. Set OPENCODE_GO_API_KEY to enable advisory chat.[/yellow]"
            )
            return

        try:
            # Build cached context for the LLM
            context = self._build_chat_context()

            with self.console.status("[cyan]Thinking...[/cyan]"):
                if context:
                    full_prompt = f"{context}\n\nUser: {prompt}"
                else:
                    full_prompt = prompt
                response = self.client.ask(full_prompt)

            if response:
                self.console.print(Markdown(response))
            else:
                self.console.print("[yellow]No response from model.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]LLM error:[/red] {e}")

    def _build_chat_context(self) -> str:
        """Build system context string from cached snapshots for chat injection."""
        snapshots = self.db.get_all_snapshots()
        if not snapshots:
            return ""

        parts = []
        parts.append("System Context (cached from last /digest or /refresh):")

        if "repos" in snapshots:
            r = snapshots["repos"]["data"]
            ts = snapshots["repos"]["updated_at"]
            enabled = [x["name"] for x in r.get("standard_repos", []) if x.get("enabled")]
            disabled = [x["name"] for x in r.get("standard_repos", []) if not x.get("enabled")]
            parts.append(
                f"  Repositories (cached {ts}): enabled={enabled}, "
                f"disabled={disabled}, warnings={r.get('warnings', [])}, "
                f"errors={r.get('errors', [])}"
            )

        if "health" in snapshots:
            h = snapshots["health"]["data"]
            ts = snapshots["health"]["updated_at"]
            parts.append(
                f"  Health (cached {ts}): CPU {h.get('cpu_pct', '?')}%, "
                f"RAM {h.get('mem_pct', '?')}%, RootFS {h.get('rootfs_pct', '?')}%, "
                f"VMs={h.get('vm_count', '?')}, LXCs={h.get('lxc_count', '?')}"
            )

        if "services" in snapshots:
            s = snapshots["services"]["data"]
            ts = snapshots["services"]["updated_at"]
            svc_list = s.get("services", [])
            running = sum(1 for sv in svc_list if sv.get("state") == "running")
            dead = [sv["name"] for sv in svc_list if sv.get("state") == "dead"]
            parts.append(
                f"  Services (cached {ts}): {running} running, "
                f"dead={dead}"
            )

        return "\n".join(parts)

    # ── Command Handlers ───────────────────────────────────────────

    def _cmd_help(self, parts: list[str]) -> None:
        """Display command reference."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Command", style="green", width=22)
        table.add_column("Description")

        for cmd, desc in COMMANDS.items():
            table.add_row(cmd, desc)

        self.console.print(table)
        self.console.print()
        self.console.print("You can also ask questions directly — they'll be sent to the LLM.")

    def _cmd_quit(self, parts: list[str]) -> None:
        """Exit the shell."""
        self.console.print("[dim]Goodbye.[/dim]")
        if self.client:
            self.client.close()
        sys.exit(0)

    def _cmd_status(self, parts: list[str]) -> None:
        """Display Proxmox resource overview."""
        if not self.proxmox:
            self.console.print("[yellow]Proxmox API not configured.[/yellow]")
            return

        try:
            status = self.proxmox.get_status()

            # Node info
            node_status = status.get("status", {})
            self.console.print(Panel(
                f"Node: [bold]{status['node']}[/bold]\n"
                f"CPU: {node_status.get('cpu', 0) * 100:.1f}%\n"
                f"Memory: {node_status.get('memory', {}).get('used', 0) / 1024**3:.1f}G / "
                f"{node_status.get('memory', {}).get('total', 0) / 1024**3:.1f}G",
                title="Proxmox Status",
                border_style="cyan",
            ))

            # VMs table
            if status.get("vms"):
                vm_table = Table(title="VMs")
                vm_table.add_column("VMID", width=6)
                vm_table.add_column("Name")
                vm_table.add_column("Status")
                vm_table.add_column("CPUs", width=6)
                vm_table.add_column("Memory", width=10)

                for vm in status["vms"]:
                    status_style = "green" if vm["status"] == "running" else "yellow"
                    mem_gb = vm.get("maxmem", 0) / 1024**3
                    vm_table.add_row(
                        str(vm["vmid"]), vm["name"],
                        Text(vm["status"], style=status_style),
                        str(vm.get("cpus", "")),
                        f"{mem_gb:.1f}G" if mem_gb else "",
                    )
                self.console.print(vm_table)

            # LXCs table
            if status.get("lxcs"):
                lxc_table = Table(title="LXCs")
                lxc_table.add_column("VMID", width=6)
                lxc_table.add_column("Name")
                lxc_table.add_column("Status")
                lxc_table.add_column("CPUs", width=6)
                lxc_table.add_column("Memory", width=10)

                for lxc in status["lxcs"]:
                    status_style = "green" if lxc["status"] == "running" else "yellow"
                    mem_gb = lxc.get("maxmem", 0) / 1024**3
                    lxc_table.add_row(
                        str(lxc["vmid"]), lxc["name"],
                        Text(lxc["status"], style=status_style),
                        str(lxc.get("cpus", "")),
                        f"{mem_gb:.1f}G" if mem_gb else "",
                    )
                self.console.print(lxc_table)

        except Exception as e:
            error_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in error_str or "SSL" in error_str:
                self.console.print(_ssl_error_panel(e))
            else:
                self.console.print(f"[red]Status error:[/red] {e}")

    def _cmd_history(self, parts: list[str]) -> None:
        """Display recent scan history."""
        try:
            with self.db._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM scan_log ORDER BY completed_at DESC LIMIT 10"
                ).fetchall()

            if not rows:
                self.console.print("[dim]No scan history yet.[/dim]")
                return

            table = Table(title="Scan History")
            table.add_column("Type", width=8)
            table.add_column("Completed")
            table.add_column("CVEs", width=6)
            table.add_column("Packages", width=10)
            table.add_column("Duration", width=10)

            for row in rows:
                table.add_row(
                    row["scan_type"],
                    str(row["completed_at"] or "pending"),
                    str(row["new_cves_found"]),
                    str(row["packages_checked"]),
                    f"{row['duration_seconds']:.1f}s" if row["duration_seconds"] else "",
                )
            self.console.print(table)
        except Exception as e:
            self.console.print(f"[red]History error:[/red] {e}")

    def _cmd_digest(self, parts: list[str]) -> None:
        """Run full CVE scan and display LLM summary."""
        if not self.client:
            self.console.print("[yellow]LLM unavailable — scan results stored but not summarized.[/yellow]")

        self.console.print("[cyan]Running CVE scan...[/cyan]")
        try:
            from src.cve_scanner import CVEScanner

            cve_cfg = self.config.get("cve", {})
            scanner = CVEScanner(
                self.db,
                nvd_api_key=cve_cfg.get("nvd_api_key"),
                nvd_rate_limit=cve_cfg.get("nvd_rate_limit", 5),
                mitre_enabled=cve_cfg.get("mitre_api_enabled", True),
                exploitdb_enabled=cve_cfg.get("exploitdb_enabled", True),
                pve_security_enabled=cve_cfg.get("pve_security_enabled", True),
                pve_sa_feed_url=cve_cfg.get("pve_sa_feed_url"),
            )

            # Sync PVE advisories first
            if cve_cfg.get("pve_security_enabled", True):
                new_advisories = scanner.sync_pve_advisories()
                if new_advisories:
                    self.console.print(f"[dim]PVE-SA sync: {new_advisories} new advisories[/dim]")

            # Get host packages if Proxmox is available
            packages = []
            if self.proxmox:
                packages = self.proxmox.get_host_packages()

            # Get repo status for LLM context
            repo_context = ""
            repo_summary = ""
            repo_data = None
            if self.proxmox:
                try:
                    repos = self.proxmox.get_host_repos()
                    repo_data = repos
                    enabled = [r["name"] for r in repos["standard_repos"] if r["enabled"]]
                    disabled = [r["name"] for r in repos["standard_repos"] if not r["enabled"]]
                    repo_context = (
                        f"APT Repositories: enabled={enabled}, disabled={disabled}\n"
                        f"Warnings: {repos['warnings']}\n"
                        f"Errors: {repos['errors']}"
                    )
                    repo_summary = (
                        f"Repos: {', '.join(enabled) if enabled else 'none enabled'}"
                    )
                except Exception:
                    repo_context = "APT Repositories: unable to query (pending verification)"

            # Get health summary for LLM context
            health_context = ""
            health_data = None
            if self.proxmox:
                try:
                    h = self.proxmox.get_health()
                    health_data = h
                    health_context = (
                        f"System Health: CPU {h['cpu_pct']}%, "
                        f"RAM {h['mem_pct']}%, "
                        f"RootFS {h['rootfs_pct']}%, "
                        f"Storage: {', '.join(s['name'] + ' ' + str(s['pct']) + '%' for s in h['storage'])}, "
                        f"Disks: {len(h['disks'])} {'PASSED' if all(d['health'] == 'PASSED' for d in h['disks']) else 'ISSUE'}"
                    )
                except Exception:
                    health_context = "System Health: unable to query (pending verification)"

            # Cache system snapshots for chat context (zero extra API calls)
            if self.proxmox:
                try:
                    if repo_data:
                        self.db.cache_snapshot("repos", repo_data)
                    if health_data:
                        self.db.cache_snapshot("health", health_data)
                    services = self.proxmox.get_service_status()
                    if services:
                        self.db.cache_snapshot("services", {"services": services})
                except Exception:
                    pass  # Cache failure is non-fatal

            result = scanner.scan_host(packages=packages)

            # Local LXC package scan
            lxc_result = scanner.scan_local_packages(packages=[])
            scanner.close()

            self.console.print(Panel(
                f"Host scan: {result['cves_found']} CVEs, {result['packages_checked']} packages\n"
                f"LXC scan:  {lxc_result['cves_matched']} matches, {lxc_result['packages_checked']} packages\n"
                f"{repo_summary}\n"
                f"Duration:  {result['duration'] + lxc_result['duration']:.1f}s",
                title="Scan Results",
                border_style="green",
            ))

            # Show matched CVEs if any
            if lxc_result.get("matched_cves"):
                table = Table(title="Matched CVEs (local packages)")
                table.add_column("CVE ID", width=20)
                table.add_column("Package", width=16)
                table.add_column("Version", width=14)
                table.add_column("Severity", width=10)
                table.add_column("CVSS", width=6)

                for m in lxc_result["matched_cves"][:20]:
                    sev = m.get("severity", "UNKNOWN")
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
                    table.add_row(
                        m["cve_id"], m["package"], m["version"],
                        Text(sev, style=color), str(m.get("cvss_score", "")),
                    )
        self.console.print(table)

    def _cmd_refresh(self, parts: list[str]) -> None:
        """Update cached system context from Proxmox API."""
        if not self.proxmox:
            self.console.print("[yellow]Proxmox API not configured.[/yellow]")
            return

        snap_type = parts[1].lower() if len(parts) >= 2 else "all"
        valid = {"repos", "health", "services", "all"}
        if snap_type not in valid:
            self.console.print(f"[red]Invalid type:[/red] {snap_type}")
            self.console.print(f"Valid: {', '.join(sorted(valid))}")
            return

        refreshed = []
        try:
            if snap_type in ("repos", "all"):
                repos = self.proxmox.get_host_repos()
                self.db.cache_snapshot("repos", repos)
                refreshed.append("repos")

            if snap_type in ("health", "all"):
                health = self.proxmox.get_health()
                self.db.cache_snapshot("health", health)
                refreshed.append("health")

            if snap_type in ("services", "all"):
                services = self.proxmox.get_service_status()
                self.db.cache_snapshot("services", {"services": services})
                refreshed.append("services")

            self.console.print(f"[green]Cached: {', '.join(refreshed)}[/green]")
            self.console.print("[dim]Use /digest for full CVE scan + cache update[/dim]")
        except Exception as e:
            error_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in error_str or "SSL" in error_str:
                self.console.print(_ssl_error_panel(e))
            else:
                self.console.print(f"[red]Refresh error:[/red] {e}")
                if len(lxc_result["matched_cves"]) > 20:
                    self.console.print(f"[dim]... and {len(lxc_result['matched_cves']) - 20} more[/dim]")

            # LLM summary
            if self.client and result["cves_found"] > 0:
                with self.console.status("[cyan]Generating LLM summary...[/cyan]"):
                    summary_prompt = (
                        f"Summarize these CVE scan results and provide prioritized recommendations:\n"
                        f"- {result['cves_found']} CVEs found\n"
                        f"- {result['packages_checked']} packages checked\n"
                        f"- Duration: {result['duration']:.1f}s"
                    )
                    if repo_context:
                        summary_prompt += f"\n\nSystem context:\n{repo_context}"
                    if health_context:
                        summary_prompt += f"\n{health_context}"
                    summary = self.client.ask(summary_prompt)
                if summary:
                    self.console.print(Markdown(summary))
        except Exception as e:
            error_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in error_str or "SSL" in error_str:
                self.console.print(_ssl_error_panel(e))
            else:
                self.console.print(f"[red]Scan error:[/red] {e}")

    def _cmd_cve(self, parts: list[str]) -> None:
        """CVE subcommands: check <pkg>, scan."""
        if len(parts) < 2:
            self.console.print("[red]Usage:[/red] /cve check <package> or /cve scan")
            return

        subcmd = parts[1].lower()

        if subcmd == "check" and len(parts) >= 3:
            package = parts[2]
            self._cve_check_package(package)
        elif subcmd == "scan":
            self._cmd_digest(parts)
        else:
            self.console.print("[red]Usage:[/red] /cve check <package> or /cve scan")

    def _cve_check_package(self, package: str) -> None:
        """Deep-dive a specific package's CVEs."""
        try:
            cves = self.db.get_cves_for_package(package)
            if not cves:
                self.console.print(f"[dim]No CVEs recorded for '{package}'.[/dim]")
                return

            table = Table(title=f"CVEs for {package}")
            table.add_column("CVE ID", width=20)
            table.add_column("Severity", width=10)
            table.add_column("CVSS", width=6)
            table.add_column("Description", max_width=60)

            for cve in cves:
                sev = cve.get("severity", "UNKNOWN")
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
                table.add_row(
                    cve["id"],
                    Text(sev, style=color),
                    str(cve.get("cvss_score", "")),
                    (cve.get("description", "") or "")[:120],
                )
            self.console.print(table)

            # LLM deep-dive
            if self.client:
                with self.console.status("[cyan]Analyzing...[/cyan]"):
                    analysis = self.client.ask(
                        f"Analyze the security posture of package '{package}' "
                        f"with {len(cves)} known CVEs. Provide remediation guidance."
                    )
                if analysis:
                    self.console.print(Markdown(analysis))
        except Exception as e:
            self.console.print(f"[red]CVE check error:[/red] {e}")

    def _cmd_guardrails(self, parts: list[str]) -> None:
        """Show or switch security framework preset."""
        presets = list_presets()

        if len(parts) < 2:
            # Show current preset
            guard = self.config.get("guardrails", {})
            current = guard.get("preset", "general") if guard.get("enabled") else "disabled"
            self.console.print(f"Current guardrail preset: [bold cyan]{current}[/bold cyan]")
            self.console.print()

            table = Table(title="Available Presets")
            table.add_column("Preset", style="green")
            table.add_column("Description")
            for name, desc in presets.items():
                marker = " ← current" if name == current else ""
                table.add_row(name + marker, desc)
            self.console.print(table)
            self.console.print("\nSwitch with: [bold]/guardrails <preset>[/bold]")
        else:
            new_preset = parts[1].lower()
            if new_preset not in presets:
                self.console.print(f"[red]Unknown preset:[/red] {new_preset}")
                self.console.print(f"Available: {', '.join(presets)}")
                return

            # Update config and reinitialize client
            self.config.setdefault("guardrails", {})["preset"] = new_preset
            if self.client:
                self.client.close()
            self.client = self._init_client()
            self.console.print(f"Guardrail preset switched to [bold cyan]{new_preset}[/bold cyan]")

    def _cmd_proxmox(self, parts: list[str]) -> None:
        """Execute Proxmox API operation with permission gating."""
        if not self.proxmox:
            self.console.print("[yellow]Proxmox API not configured.[/yellow]")
            return

        if len(parts) < 2:
            self.console.print("[red]Usage:[/red] /proxmox <action> [args...]")
            self.console.print("Examples:")
            self.console.print("  /proxmox status")
            self.console.print("  /proxmox start 100")
            self.console.print("  /proxmox stop 101")
            return

        action = parts[1].lower()
        detail = " ".join(parts[2:]) if len(parts) > 2 else ""

        # Check permission
        if not self.gate.request_confirmation(action, detail):
            self.console.print("[yellow]Operation denied.[/yellow]")
            return

        # Execute based on action
        try:
            if action == "status":
                self._cmd_status(parts)
            elif action in ("start", "stop"):
                vmid = int(parts[2]) if len(parts) > 2 else None
                if not vmid:
                    self.console.print("[red]VMID required.[/red]")
                    return

                if action == "start":
                    try:
                        result = self.proxmox.start_vm(vmid)
                        self.console.print(f"[green]VM {vmid} started.[/green]")
                    except Exception:
                        result = self.proxmox.start_lxc(vmid)
                        self.console.print(f"[green]LXC {vmid} started.[/green]")
                else:
                    try:
                        result = self.proxmox.stop_vm(vmid)
                        self.console.print(f"[green]VM {vmid} stopped.[/green]")
                    except Exception:
                        result = self.proxmox.stop_lxc(vmid)
                        self.console.print(f"[green]LXC {vmid} stopped.[/green]")
            else:
                api_path = "/".join(parts[1:])
                result = self.proxmox.run_command(f"/{api_path}", method="get")
                self.console.print(result)
        except PermissionError as e:
            self.console.print(f"[red]Permission denied:[/red] {e}")
        except Exception as e:
            error_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in error_str or "SSL" in error_str:
                self.console.print(_ssl_error_panel(e))
            else:
                self.console.print(f"[red]Proxmox error:[/red] {e}")

    # ── Health Command ─────────────────────────────────────────────

    def _cmd_health(self, parts: list[str]) -> None:
        """Hypervisor health dashboard."""
        if not self.proxmox:
            self.console.print("[yellow]Proxmox API not configured.[/yellow]")
            return

        if len(parts) >= 2:
            subcmd = parts[1].lower()
            if subcmd == "rrd":
                self._health_rrd(parts[2:] if len(parts) > 2 else [])
            elif subcmd == "services":
                self._health_services()
            else:
                self.console.print(f"[red]Unknown subcommand:[/red] {subcmd}")
                self.console.print("Usage: /health [rrd [period]|services]")
            return

        self._health_dashboard()

    def _health_dashboard(self) -> None:
        """Full hypervisor health dashboard."""
        try:
            health = self.proxmox.get_health()
        except Exception as e:
            error_str = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in error_str or "SSL" in error_str:
                self.console.print(_ssl_error_panel(e))
            else:
                self.console.print(f"[red]Health error:[/red] {e}")
            return

        # Helper functions
        def pct_color(pct: float, yellow: float, red: float) -> str:
            if pct >= red:
                return f"[red]{pct:.1f}%[/red]"
            if pct >= yellow:
                return f"[yellow]{pct:.1f}%[/yellow]"
            return f"[green]{pct:.1f}%[/green]"

        def fmt_bytes(b: int) -> str:
            if b >= 1024**4:
                return f"{b / 1024**4:.1f}T"
            if b >= 1024**3:
                return f"{b / 1024**3:.1f}G"
            if b >= 1024**2:
                return f"{b / 1024**2:.1f}M"
            return f"{b}B"

        def fmt_uptime(seconds: int) -> str:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            mins = (seconds % 3600) // 60
            if days > 0:
                return f"{days}d {hours}h {mins}m"
            return f"{hours}h {mins}m"

        # Build panel content
        lines = []
        lines.append(f"Node: [bold]{health['node']}[/bold]  |  {health.get('pveversion', '')}")
        lines.append(f"Kernel: {health.get('kernel', '')}  |  Uptime: {fmt_uptime(health.get('uptime', 0))}")
        lines.append("")

        # CPU
        load = health.get("loadavg", ["", "", ""])
        lines.append(
            f"CPU:  {pct_color(health['cpu_pct'], 80, 95)} "
            f"({health['cpu_cores']} cores, {health['cpu_sockets']} sockets)  "
            f"Load: {load[0]} {load[1]} {load[2]}"
        )

        # Memory
        lines.append(
            f"RAM:  {fmt_bytes(health['mem_used'])} / {fmt_bytes(health['mem_total'])} "
            f"({pct_color(health['mem_pct'], 80, 95)})  "
            f"Available: {fmt_bytes(health['mem_available'])}"
        )

        # Swap
        if health["swap_total"] > 0:
            lines.append(
                f"Swap: {fmt_bytes(health['swap_used'])} / {fmt_bytes(health['swap_total'])} "
                f"({pct_color(health['swap_pct'], 50, 80)})"
            )

        # RootFS
        lines.append(
            f"Root: {fmt_bytes(health['rootfs_used'])} / {fmt_bytes(health['rootfs_total'])} "
            f"({pct_color(health['rootfs_pct'], 70, 90)})"
        )

        # Storage
        if health["storage"]:
            lines.append("")
            lines.append("Storage:")
            for s in health["storage"]:
                lines.append(
                    f"  {s['name']:12s} {s['type']:6s} "
                    f"{fmt_bytes(s['used'])} / {fmt_bytes(s['total'])} "
                    f"({pct_color(s['pct'], 75, 90)})"
                )

        # Disks
        if health["disks"]:
            lines.append("")
            lines.append("Disks:")
            for d in health["disks"]:
                health_color = "green" if d["health"] == "PASSED" else "red"
                lines.append(
                    f"  {d['devpath']} — {d['model']} — {d['size_gb']}GB — "
                    f"[{health_color}]{d['health']}[/{health_color}]"
                )

        # Temperature
        temp = health.get("temperature")
        lines.append("")
        if temp and isinstance(temp, dict):
            temp_parts = []
            for k, v in temp.items():
                if isinstance(v, (int, float)):
                    temp_parts.append(f"{k}: {v}°C")
                else:
                    temp_parts.append(f"{k}: {v}")
            lines.append(f"Temperature: {', '.join(temp_parts)}")
        else:
            lines.append(
                "Temperature: N/A — install lm-sensors + "
                "[link=https://github.com/alexleigh/pve-mods]pve-mods[/link] patch"
            )

        # Service summary
        running = sum(1 for s in health["services"] if s["state"] == "running")
        dead = sum(1 for s in health["services"] if s["state"] == "dead")
        total = len(health["services"])
        lines.append("")
        lines.append(f"Services: {running} running, {dead} dead, {total} total")

        # VM/LXC counts
        lines.append(f"Guests: {health['vm_count']} VMs, {health['lxc_count']} LXCs")

        self.console.print(Panel(
            "\n".join(lines),
            title="Proxmox Health",
            border_style="cyan",
        ))

    def _health_rrd(self, args: list[str]) -> None:
        """Historical metrics from RRD."""
        timeframe = args[0].lower() if args else "day"
        valid = {"hour", "day", "week", "month", "year"}
        if timeframe not in valid:
            self.console.print(f"[red]Invalid timeframe:[/red] {timeframe}")
            self.console.print(f"Valid: {', '.join(sorted(valid))}")
            return

        try:
            data = self.proxmox.get_rrd_metrics(timeframe=timeframe)
        except Exception as e:
            self.console.print(f"[red]RRD error:[/red] {e}")
            return

        if not data:
            self.console.print("[dim]No RRD data available.[/dim]")
            return

        # Show latest values in a table
        latest = data[-1]
        table = Table(title=f"RRD Metrics — {timeframe} (latest of {len(data)} points)")
        table.add_column("Metric", style="cyan")
        table.add_column("Value")

        metrics = [
            ("CPU", f"{latest.get('cpu', 0) * 100:.1f}%"),
            ("Memory Used", f"{latest.get('memused', 0) / 1024**3:.1f}G"),
            ("Memory Total", f"{latest.get('memtotal', 0) / 1024**3:.1f}G"),
            ("Memory Available", f"{latest.get('memavailable', 0) / 1024**3:.1f}G"),
            ("Swap Used", f"{latest.get('swapused', 0) / 1024**3:.1f}G"),
            ("Root Used", f"{latest.get('rootused', 0) / 1024**3:.1f}G"),
            ("Root Total", f"{latest.get('roottotal', 0) / 1024**3:.1f}G"),
            ("Net In", f"{latest.get('netin', 0) / 1024:.1f} KB/s"),
            ("Net Out", f"{latest.get('netout', 0) / 1024:.1f} KB/s"),
            ("Load Avg", f"{latest.get('loadavg', 0):.2f}"),
            ("I/O Wait", f"{latest.get('iowait', 0) * 100:.4f}%"),
        ]
        for name, value in metrics:
            table.add_row(name, value)

        self.console.print(table)

    def _health_services(self) -> None:
        """All Proxmox services with status."""
        try:
            services = self.proxmox.get_service_status()
        except Exception as e:
            self.console.print(f"[red]Services error:[/red] {e}")
            return

        table = Table(title="Proxmox Services")
        table.add_column("Service", style="cyan")
        table.add_column("State", width=10)

        # Known expected-dead services (single-node, no HA)
        expected_dead = {
            "corosync", "pve-ha-crm", "pve-ha-lrm",
            "syslog", "systemd-timesyncd",
        }

        for s in sorted(services, key=lambda x: x["name"]):
            state = s["state"]
            if state == "running":
                state_str = "[green]running[/green]"
            elif state == "dead":
                if s["name"] in expected_dead:
                    state_str = "[dim]dead (expected)[/dim]"
                else:
                    state_str = "[yellow]dead[/yellow]"
            else:
                state_str = state
            table.add_row(s["name"], state_str)

        self.console.print(table)


# ── Entry Point ────────────────────────────────────────────────────

def main() -> None:
    """Entry point for pve-sentinel CLI."""
    shell = SentinelShell()
    shell.run()


if __name__ == "__main__":
    main()
