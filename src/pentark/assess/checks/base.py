"""Check interface.

Each vulnerability class is a self-contained :class:`Check` that takes a context
(HTTP client + target) and returns findings. Keeping checks behind one small
interface makes them independently testable and lets the runner treat breadth
uniformly (register a class, it runs).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from pentark.assess.http_client import HttpClient
from pentark.assess.models import Finding


@dataclass
class CheckContext:
    http: HttpClient
    target: str


class Check(ABC):
    id: str = "abstract"
    name: str = "abstract"

    @abstractmethod
    def run(self, ctx: CheckContext) -> list[Finding]:
        ...


__all__ = ["Check", "CheckContext"]
