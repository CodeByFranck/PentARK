"""Optional external confirmers for injection findings.

Both are off by default and injectable, so the core scanner stays dependency-free
and fully offline-testable. They are intentionally minimal and non-destructive:

* :class:`SqlmapConfirmer` runs sqlmap with ``--banner`` only — it confirms the
  injection and reads the DBMS **version banner**, never ``--dump``.
* :class:`PlaywrightConfirmer` loads a URL in a headless browser and reports
  whether an ``alert(document.domain)`` dialog actually fires (real DOM execution).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol

from pentark.assess.injection.params import InjectionPoint, build_request


@dataclass(frozen=True)
class SqlmapResult:
    confirmed: bool
    banner: str = ""       # DBMS version string only
    detail: str = ""


class SqlmapLike(Protocol):
    def confirm(self, point: InjectionPoint, value: str) -> SqlmapResult: ...


class XssConfirmerLike(Protocol):
    def confirm(self, url: str) -> bool: ...


class SqlmapConfirmer:
    """Shell out to sqlmap for confirmation + version banner (no data dump)."""

    def __init__(self, *, binary: str = "sqlmap", timeout: float = 180.0) -> None:
        self.binary = binary
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def confirm(self, point: InjectionPoint, value: str) -> SqlmapResult:
        if not self.available:
            return SqlmapResult(False, detail="sqlmap not installed")
        method, url, data = build_request(point, value)
        cmd = [
            self.binary, "-u", url, "--batch", "--flush-session",
            "--level", "1", "--risk", "1", "--banner",
        ]
        if data is not None:
            cmd += ["--data", "&".join(f"{k}={v}" for k, v in data.items())]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            ).stdout
        except (subprocess.SubprocessError, OSError) as exc:
            return SqlmapResult(False, detail=f"sqlmap error: {exc}")
        confirmed = "is vulnerable" in out or "sqlmap identified" in out
        banner = ""
        for line in out.splitlines():
            if "banner:" in line.lower():
                banner = line.split(":", 1)[1].strip().strip("'")
                break
        return SqlmapResult(confirmed, banner=banner, detail="sqlmap")


class PlaywrightConfirmer:
    """Confirm real DOM XSS: load the URL headless, watch for the alert dialog."""

    def __init__(self, *, timeout_ms: int = 8000) -> None:
        self.timeout_ms = timeout_ms

    def confirm(self, url: str) -> bool:
        try:
            from playwright.sync_api import sync_playwright  # optional dependency
        except ImportError:
            return False
        fired = {"v": False}
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()

                def _on_dialog(dialog):
                    # alert(document.domain) -> the page's own domain in the message
                    fired["v"] = True
                    dialog.dismiss()

                page.on("dialog", _on_dialog)
                page.goto(url, timeout=self.timeout_ms, wait_until="load")
                page.wait_for_timeout(500)
                browser.close()
        except Exception:
            return False
        return fired["v"]


__all__ = [
    "SqlmapResult", "SqlmapLike", "XssConfirmerLike",
    "SqlmapConfirmer", "PlaywrightConfirmer",
]
