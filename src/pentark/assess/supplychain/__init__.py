"""A03 – Software Supply Chain Failures: component fingerprinting + OSV lookup.

Detection only. Fingerprints JS libraries / frameworks from response headers,
`<script>` tags, inline version banners, and (if reachable) `package.json` /
`package-lock.json`, then cross-references npm components against the OSV.dev
vulnerability database.

Two HTTP paths, deliberately separate:
  * the **target** is read through the scope-gated :class:`HttpClient` (so scope,
    throttle, and audit all apply);
  * **OSV.dev** is a third-party service, not the target, so it is queried through
    its own :class:`OsvClient` (a plain httpx client) — which is why it would be
    wrong to route it through the target's scope allowlist.
"""

from pentark.assess.supplychain.check import SupplyChainCheck
from pentark.assess.supplychain.models import Component, Vulnerability
from pentark.assess.supplychain.osv import OsvClient

__all__ = ["SupplyChainCheck", "Component", "Vulnerability", "OsvClient"]
