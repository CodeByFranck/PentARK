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

import datetime as dt
import json
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pentark import __version__
from pentark.assess.http_client import HttpClient
from pentark.assess.models import AssessmentResult
from pentark.assess.runner import AssessmentRunner
from pentark.core.audit import AuditLog
from pentark.core.banner import render_banner
from pentark.core.errors import ConfigError, PentarkError
from pentark.core.ratelimit import RateLimiter
from pentark.core.scope import Scope, load_scope
from pentark.exploit import ExploitSession, Pymetasploit3Client
from pentark.preflight import check_tools
from pentark.report import ReportMeta, write_markdown, write_pdf
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
    report: str = typer.Option(
        None, "--report", help="also write a report to this path/basename (see --report-format)"
    ),
    report_format: str = typer.Option(
        "md", "--report-format", help="report format when --report is used: md | pdf | both"
    ),
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

    # Stamp when/who/what so a report generated from this JSON is self-describing.
    result.meta.update(
        {
            "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            "operator": sc.authorization.operator,
            "tool_version": __version__,
        }
    )

    _print_findings(result)

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"\nWrote prioritized findings to [bold]{output}[/bold]")
    if report:
        meta = _report_meta(sc)
        for fmt_name, path in _report_paths(report, report_format):
            _write_report(result, meta, fmt_name, path)
    console.print(f"Audit log: [bold]{sc.settings.audit_path}[/bold]")


@app.command()
def report(
    findings: str = typer.Argument(..., help="path to a findings JSON produced by `assess`"),
    output: str = typer.Option(None, "--output", "-o", help="output path or basename (default: report)"),
    format: str = typer.Option("md", "--format", "-f", help="report format: md | pdf | both"),
    config: str = typer.Option(
        "scope.yaml", "--config", "-c", help="scope.yaml (optional; adds operator/scope to the report)"
    ),
) -> None:
    """Turn a findings JSON into a professional Markdown and/or PDF report."""
    result = _load_findings(findings)

    # Scope is optional for reporting — enrich the report if it is available.
    sc: Scope | None = None
    try:
        sc = load_scope(config)
    except PentarkError:
        sc = None
    meta = _report_meta(sc)

    for fmt_name, path in _report_paths(output, format):
        _write_report(result, meta, fmt_name, path)


def _load_findings(findings: str) -> AssessmentResult:
    """Load a findings JSON produced by `assess` back into an AssessmentResult."""
    fpath = Path(findings)
    if not fpath.is_file():
        raise ConfigError(f"findings file not found: {fpath}. Run `pentark assess ... --output {fpath.name}` first.")
    try:
        data = json.loads(fpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid findings JSON in {fpath}: {exc}") from exc
    try:
        return AssessmentResult.from_dict(data)
    except ValueError as exc:
        raise ConfigError(f"unrecognized findings JSON in {fpath}: {exc}") from exc


def _report_meta(sc: Scope | None) -> ReportMeta:
    if sc is None:
        return ReportMeta.now(__version__)
    return ReportMeta.now(
        __version__,
        operator=(sc.authorization.operator or None),
        scope_hosts=tuple(sc.hosts),
        scope_prefixes=tuple(sc.url_prefixes),
    )


def _report_paths(output: str | None, fmt: str) -> list[tuple[str, Path]]:
    fmt = (fmt or "").lower()
    if fmt not in {"md", "pdf", "both"}:
        raise ConfigError(f"--format must be one of md, pdf, both (got {fmt!r}).")
    stem = output or "report"
    for ext in (".md", ".pdf"):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    paths: list[tuple[str, Path]] = []
    if fmt in ("md", "both"):
        paths.append(("md", Path(stem + ".md")))
    if fmt in ("pdf", "both"):
        paths.append(("pdf", Path(stem + ".pdf")))
    return paths


def _write_report(result, meta: ReportMeta, fmt_name: str, path: Path) -> None:
    if fmt_name == "md":
        write_markdown(result, meta, path)
    else:
        write_pdf(result, meta, path)
    console.print(f"[green]Wrote[/green] {fmt_name.upper()} report to [bold]{path}[/bold]")


@app.command()
def exploit(
    findings: str = typer.Argument(..., help="findings JSON produced by `assess`"),
    target: str = typer.Option(None, "--target", "-t", help="target to act on (default: the assessed target in the JSON)"),
    config: str = typer.Option("scope.yaml", "--config", "-c", help="path to scope.yaml"),
    check: bool = typer.Option(False, "--check", help="run Metasploit's non-destructive check/scan for suggested modules"),
    run: bool = typer.Option(False, "--run", help="run the exploit module — fires a payload (requires --unsafe)"),
    unsafe: bool = typer.Option(False, "--unsafe", help="permit a real, potentially destructive exploit (turns safe-mode OFF)"),
    module: str = typer.Option(None, "--module", "-m", help="only act on this exact module path"),
    yes: bool = typer.Option(False, "--yes", "-y", help="assume yes to confirmations (safe-mode still applies)"),
    msf_host: str = typer.Option("127.0.0.1", "--msf-host", help="msfrpcd host"),
    msf_port: int = typer.Option(55553, "--msf-port", help="msfrpcd port"),
    msf_ssl: bool = typer.Option(True, "--msf-ssl/--no-msf-ssl", help="connect to msfrpcd over SSL"),
) -> None:
    """Offer — and optionally run — Metasploit modules for confirmed findings.

    Default is suggestions only: nothing is sent to the target. `--check` runs a
    non-destructive Metasploit check/scan (needs a running msfrpcd). `--run
    --unsafe` fires a real exploit, and only after an explicit per-module
    confirmation. Exploitation is never automatic.
    """
    sc = load_scope(config)
    render_banner(sc, console)
    sc.require_authorization()

    result = _load_findings(findings)
    tgt = target or result.target
    sc.require_in_scope(tgt)                 # refuse off-scope up front

    audit = AuditLog(sc.settings.audit_path)
    audit.log("run.start", target=tgt, operator=sc.authorization.operator, phase="exploit")

    session = ExploitSession(sc, audit=audit)
    suggestions = session.suggest(result.findings)
    _print_suggestions(tgt, suggestions)

    if not (check or run):
        console.print(
            "\n[dim]Suggestions only — nothing was sent to the target. Add "
            "[bold]--check[/bold] for a safe Metasploit check, or "
            "[bold]--run --unsafe[/bold] to fire a real exploit.[/dim]"
        )
        console.print(f"Audit log: [bold]{sc.settings.audit_path}[/bold]")
        return

    targets = [m for s in suggestions for m in s.modules if not module or m.path == module]
    if not targets:
        msg = f" (no match for --module {module})" if module else ""
        console.print(f"\n[yellow]No suggested modules to act on.[/yellow]{msg}")
        return

    if run and not unsafe:
        console.print(
            "\n[red]Refusing to run:[/red] --run fires a real exploit and requires "
            "[bold]--unsafe[/bold] (safe-mode is on by default). Use --check for a safe check."
        )
        raise typer.Exit(code=2)

    # Connect to Metasploit only now that an active action is actually requested.
    password = os.environ.get("MSF_RPC_PASSWORD", "")
    client = Pymetasploit3Client(host=msf_host, port=msf_port, password=password, ssl=msf_ssl)
    confirm = (lambda _m: True) if yes else typer.confirm
    session = ExploitSession(sc, client, audit=audit)
    try:
        for mod in targets:
            outcome = (
                session.exploit(tgt, mod, confirm=confirm, allow_unsafe=unsafe)
                if run
                else session.check(tgt, mod, confirm=confirm)
            )
            _print_outcome(outcome)
    finally:
        client.close()
    console.print(f"\nAudit log: [bold]{sc.settings.audit_path}[/bold]")


_STATUS_STYLE = {
    "vulnerable": "bold red",
    "success": "bold red",
    "safe": "green",
    "failed": "yellow",
    "refused": "dim",
    "skipped": "dim",
    "unsupported": "dim",
    "unknown": "cyan",
    "error": "red",
}


def _print_suggestions(target: str, suggestions) -> None:
    if not suggestions:
        console.print(
            "\n[green]No Metasploit modules matched the findings.[/green] "
            "(Nothing to offer for this finding set.)"
        )
        return
    table = Table(title=f"Suggested modules for {target}  (offer only — not run)")
    table.add_column("Finding", overflow="fold")
    table.add_column("Module")
    table.add_column("Type")
    table.add_column("Why", overflow="fold")
    for s in suggestions:
        for m in s.modules:
            table.add_row(s.finding_name, m.path, m.module_type, m.rationale)
    console.print(table)


def _print_outcome(o) -> None:
    style = _STATUS_STYLE.get(o.status, "")
    status = f"[{style}]{o.status}[/{style}]" if style else o.status
    detail = f"  [dim]({o.detail})[/dim]" if o.detail else ""
    console.print(f"  {o.action}: [bold]{o.module}[/bold] → {status}{detail}")


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
