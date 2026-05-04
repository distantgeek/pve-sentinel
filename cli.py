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

# ── Constants ──────────────────────────────────────────────────────

VERSION = "0.2.0"
HISTORY_FILE = str(Path.home() / ".config" / "pve-sentinel" / "cli_history")

COMMANDS = {
    "/digest": "Run full CVE scan and LLM summary",
    "/cve check <pkg>": "Deep-dive a specific package",
    "/cve scan": "Run host-only CVE scan",
    "/status": "Proxmox resource overview",
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
    console.print(f"  pve-sentinel v{VERSION} — LLM-driven security advisory agent")
    console.print()


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
            with self.console.status("[cyan]Thinking...[/cyan]"):
                response = self.client.ask(prompt)

            if response:
                self.console.print(Markdown(response))
            else:
                self.console.print("[yellow]No response from model.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]LLM error:[/red] {e}")

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

            scanner = CVEScanner(self.db)
            # Get host packages if Proxmox is available
            packages = []
            if self.proxmox:
                packages = self.proxmox.get_host_packages()

            result = scanner.scan_host(packages=packages)
            scanner.close()

            self.console.print(Panel(
                f"Scan complete in {result['duration']:.1f}s\n"
                f"CVEs found: {result['cves_found']}\n"
                f"Packages checked: {result['packages_checked']}",
                title="Scan Results",
                border_style="green",
            ))

            # LLM summary
            if self.client and result["cves_found"] > 0:
                with self.console.status("[cyan]Generating LLM summary...[/cyan]"):
                    summary = self.client.ask(
                        f"Summarize these CVE scan results and provide prioritized recommendations:\n"
                        f"- {result['cves_found']} CVEs found\n"
                        f"- {result['packages_checked']} packages checked\n"
                        f"- Duration: {result['duration']:.1f}s"
                    )
                if summary:
                    self.console.print(Markdown(summary))
        except Exception as e:
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
                    # Try VM first, then LXC
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
                # Generic API call via run_command (read-only or gated)
                api_path = "/".join(parts[1:])
                result = self.proxmox.run_command(f"/{api_path}", method="get")
                self.console.print(result)
        except PermissionError as e:
            self.console.print(f"[red]Permission denied:[/red] {e}")
        except Exception as e:
            self.console.print(f"[red]Proxmox error:[/red] {e}")


# ── Entry Point ────────────────────────────────────────────────────

def main() -> None:
    """Entry point for pve-sentinel CLI."""
    shell = SentinelShell()
    shell.run()


if __name__ == "__main__":
    main()
