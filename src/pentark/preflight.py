"""Dependency preflight — check that the external tools we orchestrate are present.

The assessment MVP (headers + reflected XSS) needs no external tools, but later
phases orchestrate these. Reporting presence early keeps failures friendly and
up-front rather than mid-scan.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

# tool -> what it's used for
_TOOLS = {
    "sqlmap": "SQL injection (assessment)",
    "nikto": "server misconfiguration (assessment)",
    "nuclei": "templated vulnerability checks (assessment)",
    "whatweb": "technology fingerprinting (assessment)",
    "msfrpcd": "Metasploit RPC (exploitation phase)",
}


@dataclass
class ToolStatus:
    name: str
    purpose: str
    path: str | None

    @property
    def present(self) -> bool:
        return self.path is not None


def check_tools() -> list[ToolStatus]:
    return [ToolStatus(name, purpose, shutil.which(name)) for name, purpose in _TOOLS.items()]


__all__ = ["ToolStatus", "check_tools"]
