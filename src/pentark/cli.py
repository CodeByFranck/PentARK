"""Command-line interface (typer + rich).

Commands:
  * ``scope``      — validate scope.yaml and show the authorization/allowlist
  * ``preflight``  — check external tools are installed
  * ``assess``     — run the assessment phase against an in-scope target
  * ``version``

Every command that touches a target prints the consent banner and enforces the
authorization gate first, so you cannot scan without being shown — and passing —
the authorization boundary. Exploitation is intentionally NOT wired up yet.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pentark import __version__
from pentark.assess.http_client import HttpClient
from pentark.assess.runner import AssessmentRunner
from pentark.core.audit import AuditLog
from pentark.core.banner import render_banner
from pentark.core.errors import PentarkError
from pentark.core.ratelimit import RateLimiter
from pentark.core.scope import load_scope
from pentark.preflight import check_tools
from pentark.scaffold import build_scope_yaml, normalize_targets, run_init

app = typer.Typer(add_completion=False, help="PentARK — authorized-use web app pentest framework.")
console = Console()
err = Console(stderr=True)

_SEV_STYLE = {
    "Critical": "bold white on red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "None": "dim",
}


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"pentark {__version__}")


@app.command()
def init(config: str = typer.Option("scope.yaml", "--config", "-c", help="where to write scope.yaml")) -> None:
    """Interactively create scope.yaml — just type your authorized targets."""
    def _ask(prompt: str, default: str) -> str:
        return typer.prompt(prompt, default=default, show_default=bool(default))

    def _confirm(prompt: str) -> bool:
        return typer.confirm(prompt, default=False)

    run_init(_ask, _confirm, console.print, path=config)


@app.command("add-target")
def add_target(
    target: str = typer.Argument(..., help="host/IP or URL to authorize"),
    config: str = typer.Option("scope.yaml", "--config", "-c", help="path to scope.yaml"),
) -> None:
    """Add one authorized target to an existing scope.yaml (no editing)."""
    sc = load_scope(config)  # must already exist (run `init` first)
    add_hosts, add_prefixes = normalize_targets([target])
    hosts = list(dict.fromkeys(list(sc.hosts) + add_hosts))
    prefixes = list(dict.fromkeys(list(sc.url_prefixes) + add_prefixes))
    text = build_scope_yaml(
        operator=sc.authorization.operator,
        acknowledgement=sc.authorization.acknowledgement,
        signed=sc.authorization.signed,
        expires=sc.authorization.expires.isoformat() if sc.authorization.expires else None,
        hosts=hosts,
        url_prefixes=prefixes,
        rate_limit_rps=sc.settings.rate_limit_rps,
        timeout_seconds=sc.settings.timeout_seconds,
        user_agent=sc.settings.user_agent,
        audit_path=sc.settings.audit_path,
        authorized=sc.authorization.authorized,
    )
    Path(config).write_text(text, encoding="utf-8")
    console.print(f"[green]Added[/green] to scope: {target}")
    console.print(f"In scope now: {hosts + prefixes}")


@app.command()
def scope(config: str = typer.Option("scope.yaml", "--config", "-c", help="path to scope.yaml")) -> None:
    """Validate scope.yaml and show the authorization + allowlist."""
    sc = load_scope(config)
    render_banner(sc, console)
    try:
        sc.require_authorization()
        console.print("[green]Authorization gate: PASSED[/green] - active operations are permitted.")
    except PentarkError as exc:
        console.print(f"[red]Authorization gate: BLOCKED[/red] - {exc}")


@app.command()
def preflight() -> None:
    """Check that orchestrated external tools are installed."""
    table = Table(title="External tool preflight")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Used for")
    for t in check_tools():
        status = "[green]found[/green]" if t.present else "[yellow]missing[/yellow]"
        table.add_row(t.name, status, t.purpose)
    console.print(table)


@app.command()
def assess(
    target: str = typer.Argument(..., help="target URL (must be in scope)"),
    config: str = typer.Option("scope.yaml", "--config", "-c", help="path to scope.yaml"),
    output: str = typer.Option(None, "--output", "-o", help="write prioritized findings JSON here"),
) -> None:
    """Run the assessment phase against an in-scope target."""
    sc = load_scope(config)
    render_banner(sc, console)
    sc.require_authorization()          # gate: raises if not authorized
    sc.require_in_scope(target)         # refuse off-scope targets up front

    audit = AuditLog(sc.settings.audit_path)
    audit.log("run.start", target=target, operator=sc.authorization.operator, phase="assess")

    http = HttpClient(
        sc,
        rate_limiter=RateLimiter(sc.settings.rate_limit_rps),
        audit=audit,
    )
    try:
        result = AssessmentRunner(http, audit=audit).run(target)
    finally:
        http.close()

    _print_findings(result)

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"\nWrote prioritized findings to [bold]{output}[/bold]")
    console.print(f"Audit log: [bold]{sc.settings.audit_path}[/bold]")


def _print_findings(result) -> None:
    s = result.summary()
    if not result.findings:
        console.print("\n[green]No findings.[/green] (Nothing the current checks flagged.)")
        return
    table = Table(title=f"Prioritized findings for {result.target}")
    table.add_column("Sev")
    table.add_column("CVSS")
    table.add_column("Finding")
    table.add_column("Conf.")
    table.add_column("Endpoint", overflow="fold")
    for f in result.findings:
        style = _SEV_STYLE.get(f.severity, "")
        table.add_row(
            f"[{style}]{f.severity}[/{style}]" if style else f.severity,
            f"{f.cvss_score:.1f}",
            f.name,
            f.confidence,
            f.endpoint,
        )
    console.print(table)
    summary = ", ".join(f"{n} {sev}" for sev, n in sorted(s.items()))
    console.print(f"\n{len(result.findings)} finding(s): {summary}.")


def main() -> None:
    try:
        app()
    except PentarkError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
