"""A06 – Insecure Design: semi-automated business-logic testing.

Design flaws can't be inferred from a URL, so this module is driven by a *logic
spec* (YAML/JSON) in which the operator declares what to probe: sensitive
endpoints that should be rate-limited, numeric fields that should reject
negative/overflow values, multi-step workflows that shouldn't be skippable, and
operations that should be race-safe. Findings are reported as **anomalies for
manual review** (low confidence) — the module never tries to exploit them.
"""

from pentark.assess.logic.engine import LogicScanner
from pentark.assess.logic.spec import LogicSpec, load_spec

__all__ = ["LogicScanner", "LogicSpec", "load_spec"]
