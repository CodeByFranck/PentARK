"""The scope/consent banner printed on every run.

Making the operator, authorization, and exact in-scope targets visible on every
invocation is both a usability aid and an accountability control: you can't run
the tool without being shown, and reminded of, what you're authorized to touch.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from pentark.core.scope import Scope


def render_banner(scope: Scope, console: Console | None = None) -> None:
    console = console or Console()
    a = scope.authorization
    targets = list(scope.hosts) + list(scope.url_prefixes)
    target_lines = "\n".join(f"  - {t}" for t in targets) or "  (none - default-deny)"
    expires = a.expires.isoformat() if a.expires else "—"
    body = (
        f"[bold]Operator:[/bold] {a.operator or '—'}\n"
        f"[bold]Authorized:[/bold] {'yes' if a.authorized else 'NO'}   "
        f"[bold]Signed:[/bold] {a.signed or '—'}   "
        f"[bold]Expires:[/bold] {expires}\n"
        f"[bold]In scope (active operations restricted to these):[/bold]\n{target_lines}\n\n"
        "[dim]Authorized-use only. Every action is scope-checked and audit-logged. "
        "Off-scope targets are refused.[/dim]"
    )
    console.print(Panel(body, title="PentARK - engagement scope", border_style="cyan"))


__all__ = ["render_banner"]
