"""Setup helper module for pve-sentinel.

Provides commands for initial configuration and connectivity verification.

Usage:
    uv run python -m src.setup cert       # Install Proxmox CA certificate (user-level)
    uv run python -m src.setup verify     # Test Proxmox API + LLM connectivity
    uv run python -m src.setup wizard     # Interactive setup (future)
"""

import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

console = Console()

# Load .env at module import time
for candidate in [Path(".env"), Path("advisory/.env"), Path.home() / "advisory" / ".env"]:
    if candidate.exists():
        load_dotenv(dotenv_path=candidate)
        break


def _get_proxmox_host() -> str:
    """Get Proxmox host from config or environment."""
    try:
        from src.config import load_config
        cfg = load_config()
        return cfg.get("proxmox", {}).get("host", "")
    except (FileNotFoundError, ValueError):
        return os.environ.get("PROXMOX_HOST", "")


def _get_proxmox_port() -> int:
    """Get Proxmox API port (default 8006)."""
    return 8006


def cmd_cert() -> None:
    """Fetch the Proxmox CA certificate and install it to the user-level trust store.

    This is a rootless operation. The certificate is installed to:
        ~/.local/share/ca-certificates/pve-root-ca.crt

    Note: Proxmox's default self-signed CA cert may not include the keyUsage
    extension required by modern Python/OpenSSL. If verification still fails
    after installing the cert, set verify_ssl: false in config.yaml (homelab only).
    """
    host = _get_proxmox_host()
    if not host:
        console.print(Panel(
            "[red]Proxmox host not configured.[/red]\n"
            "Set the host in config.yaml under proxmox.host, or run:\n"
            "  export PROXMOX_HOST=192.168.x.x",
            title="Error",
            border_style="red",
        ))
        sys.exit(1)

    port = _get_proxmox_port()
    console.print(f"[cyan]Fetching CA certificate from {host}:{port}...[/cyan]")

    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts"],
            input=b"Q",
            capture_output=True,
            timeout=15,
        )
    except FileNotFoundError:
        console.print("[red]openssl not found. Install it with: apt install openssl[/red]")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        console.print(f"[red]Connection to {host}:{port} timed out.[/red]")
        sys.exit(1)

    if result.returncode != 0:
        console.print(f"[red]openssl failed: {result.stderr.decode().strip()}[/red]")
        sys.exit(1)

    # Parse the certificate chain
    output = result.stdout.decode()
    certs = []
    in_cert = False
    current = []
    for line in output.split("\n"):
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            current = [line]
        elif "-----END CERTIFICATE-----" in line:
            current.append(line)
            certs.append("\n".join(current))
            in_cert = False
            current = []
        elif in_cert:
            current.append(line)

    if not certs:
        console.print("[red]No certificates found in TLS handshake.[/red]")
        sys.exit(1)

    # The last cert in the chain is the root CA
    root_ca = certs[-1]

    # Install to user-level CA trust store
    ca_dir = Path.home() / ".local" / "share" / "ca-certificates"
    ca_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca_file = ca_dir / "pve-root-ca.crt"
    fd = os.open(str(ca_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(root_ca + "\n")

    console.print(f"[green]Certificate saved to {ca_file}[/green]")

    console.print()
    console.print(Panel(
        "[green]Proxmox CA certificate saved (user-level).[/green]\n\n"
        f"Certificate: {ca_file}\n\n"
        "[yellow]Important:[/yellow] Do NOT set SSL_CERT_FILE to this file — it\n"
        "contains only the Proxmox CA and will break external HTTPS (NVD, MITRE).\n\n"
        "For homelab environments, set [bold]verify_ssl: false[/bold] in\n"
        "config.yaml instead. This is acceptable on trusted networks.\n\n"
        "For production, replace Proxmox's self-signed CA with a standards-\n"
        "compliant certificate that includes the keyUsage extension.",
        title="Next Steps",
        border_style="green",
    ))


def cmd_verify() -> None:
    """Test Proxmox API and LLM connectivity."""
    from src.config import load_config
    from src.opencode_client import OpenCodeClient
    from src.proxmox_tools import ProxmoxTools

    console.print("[cyan]Testing connectivity...[/cyan]\n")

    # Test LLM
    console.print("  LLM (OpenCode Go)... ", end="")
    try:
        client = OpenCodeClient()
        if client.health_check():
            console.print("[green]OK[/green]")
        else:
            console.print("[yellow]API reachable but /models returned non-200[/yellow]")
        client.close()
    except ValueError as e:
        console.print(f"[red]FAIL: {e}[/red]")
    except Exception as e:
        console.print(f"[red]FAIL: {e}[/red]")

    # Test Proxmox
    console.print("  Proxmox API... ", end="")
    try:
        cfg = load_config()
        pmx = cfg.get("proxmox", {})
        tools = ProxmoxTools(
            host=pmx["host"],
            user=pmx.get("user", ""),
            token_name=pmx.get("token_name", ""),
            token_value=pmx["token_value"],
            node=pmx.get("node", ""),
            verify_ssl=pmx.get("verify_ssl", True),
        )
        status = tools.get_status()
        console.print(f"[green]OK — node: {status['node']}[/green]")
    except Exception as e:
        error_str = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in error_str or "SSL" in error_str:
            console.print("[red]SSL verification failed[/red]")
            console.print(Panel(
                "Your Proxmox host uses a self-signed certificate.\n\n"
                "Fix options:\n"
                "  1. [bold]uv run python -m src.setup cert[/bold] — install the Proxmox CA cert\n"
                "  2. Set [bold]verify_ssl: false[/bold] in config.yaml (homelab only)\n\n"
                "Note: Proxmox's default CA cert may not meet modern X.509\n"
                "requirements (missing keyUsage extension). Option 2 is\n"
                "acceptable for trusted homelab environments.",
                title="SSL Certificate Error",
                border_style="red",
            ))
        else:
            console.print(f"[red]FAIL: {e}[/red]")

    console.print()


def cmd_wizard() -> None:
    """Interactive setup wizard (placeholder for future implementation)."""
    console.print(Panel(
        "[yellow]Interactive setup wizard not yet implemented.[/yellow]\n\n"
        "For now, configure pve-sentinel manually:\n\n"
        "  1. Copy config.yaml.example to config.yaml\n"
        "  2. Edit config.yaml with your Proxmox host details\n"
        "  3. Create .env with OPENCODE_GO_API_KEY and PROXMOX_TOKEN_VALUE\n"
        "  4. Run: uv run python -m src.setup cert (for SSL)\n"
        "  5. Run: uv run python -m src.setup verify (to test)",
        title="Setup Wizard",
        border_style="yellow",
    ))


def main() -> None:
    """Entry point for setup commands."""
    if len(sys.argv) < 2:
        console.print(Panel(
            "Usage: uv run python -m src.setup <command>\n\n"
            "Commands:\n"
            "  cert     Install Proxmox CA certificate (user-level, no root)\n"
            "  verify   Test Proxmox API + LLM connectivity\n"
            "  wizard   Interactive setup (not yet implemented)",
            title="pve-sentinel Setup",
            border_style="cyan",
        ))
        sys.exit(1)

    command = sys.argv[1].lower()
    commands = {
        "cert": cmd_cert,
        "verify": cmd_verify,
        "wizard": cmd_wizard,
    }

    handler = commands.get(command)
    if handler:
        handler()
    else:
        console.print(f"[red]Unknown command: {command}[/red]")
        console.print("Available: cert, verify, wizard")
        sys.exit(1)


if __name__ == "__main__":
    main()
