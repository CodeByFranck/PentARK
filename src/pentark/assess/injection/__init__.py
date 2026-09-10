"""A05 – Injection: SQLi, XSS, command injection, and SSTI.

Active testing, so it is a dedicated command (`pentark inject`), not part of the
passive default assessment. Every request still goes through the scope-gated
HttpClient. Proof-of-concept is deliberately non-destructive: it proves code/query
execution (timing, arithmetic evaluation, canary reflection, SQL errors) and, at
most, extracts a version banner — it never dumps data or modifies rows. Optional
sqlmap (`--sqlmap`, uses `--banner` only) and Playwright (`--browser`, confirms
`alert(document.domain)`) confirmers are injectable and off by default.
"""

from pentark.assess.injection.engine import InjectionScanner
from pentark.assess.injection.params import InjectionPoint

__all__ = ["InjectionScanner", "InjectionPoint"]
