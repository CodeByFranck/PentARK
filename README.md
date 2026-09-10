# PentARK

A modular **Web Application Pentest Framework** for **authorized** security
testing, built as a study/portfolio project. It runs in three phases:

| Phase | What it does | Status |
|-------|--------------|--------|
| 1. **Assessment** | Scan a target web app, classify vulnerabilities, score them with **CVSS v3.1**, and output a **prioritized** findings list. | 🟢 in progress |
| 2. **Controlled exploitation** | *Optional, user-driven.* For confirmed findings, offer matching Metasploit modules via msfrpcd — never automatic. | 🟢 in progress |
| 3. **Reporting** | Professional report (findings, CVSS, evidence, remediation) as Markdown + PDF. | 🟢 in progress |

> **Current milestone:** the safety foundation (authorization gate, scope
> allowlist, audit log, rate limiting), the assessment phase for **missing
> security headers** and a **safe reflected-XSS** check with CVSS scoring and
> prioritized JSON output, a **reporting phase** that turns those findings into a
> professional **Markdown + PDF** report, and a **controlled-exploitation phase**
> that *offers* matching Metasploit modules and runs them only under explicit,
> per-action confirmation with a non-destructive safe-mode default (a real
> exploit needs an extra opt-in). Exploitation is never automatic.

---

## ⚖️ Ethical and legal use — read this first

**Testing web applications you do not own or have explicit written permission to
test is illegal** in most jurisdictions (e.g. the U.S. Computer Fraud and Abuse
Act, the UK Computer Misuse Act, and equivalents). This project is for:

- **Authorized penetration testing** with written permission and a defined scope.
- **Security research** on applications you own or control.
- **Education / labs** — deliberately vulnerable practice targets such as
  **OWASP Juice Shop**, **DVWA**, and **Metasploitable**.

PentARK is designed to make unauthorized use *harder and more accountable*:

1. **Authorization gate.** Nothing active runs unless a `scope.yaml` exists with
   `authorized: true`, an operator, a signed acknowledgement, and a non-expired
   window. See [`core/scope.py`](src/pentark/core/scope.py).
2. **Scope allowlist (default-deny).** Every request's target is validated
   against the allowlist; anything off-scope is **refused and logged**.
3. **No automatic exploitation.** The exploitation phase only *offers* matching
   Metasploit modules. Running anything requires the target on the allowlist, an
   explicit per-action confirmation, and a non-destructive **safe-mode** default;
   firing a real exploit needs an additional explicit `--unsafe` opt-in. Every
   suggestion, check, refusal, and run is audit-logged.
4. **Consent banner + audit log.** A scope banner prints on every run, and every
   action (target, module, timestamp, result) is appended to a timestamped
   audit log.
5. **Rate limiting.** Client-side throttling so the tool can't hammer a target.

You are solely responsible for operating within the law and your rules of
engagement. The authors accept no liability for misuse.

### Recommended practice targets
- **OWASP Juice Shop** — `http://localhost:3000/`
- **DVWA** (Damn Vulnerable Web App)
- **Metasploitable 2/3**

All run locally in a VM you control — the correct place to learn.

---

## Install

```bash
python -m pip install -e ".[dev]"     # Python 3.11+ (dev tools + PDF reporting)
```

PDF reports use [reportlab](https://pypi.org/project/reportlab/) (pure Python, no
system libraries). It is included in the `dev` extra above; for a runtime install
that only needs reporting, use `pip install "pentark[report]"`. The Markdown
report needs nothing beyond the standard library.

The optional exploitation phase talks to Metasploit's RPC daemon
([`pymetasploit3`](https://pypi.org/project/pymetasploit3/)); install it with
`pip install "pentark[exploit]"`. It is only needed when you actually run a
Metasploit check/exploit — offering module suggestions needs nothing extra.

## Usage

```bash
# 1. Create your authorization/scope file by just typing your targets — no YAML editing.
pentark init
#    answer a few prompts (operator, targets you're authorized to test, attestation)

#    ...or add a target to an existing scope in one command:
pentark add-target http://192.168.56.101/

# 2. Confirm the gate and see what's in scope.
pentark scope

# 3. Check optional external tools (used by later checks/phases).
pentark preflight

# 4. Run the assessment against an in-scope target.
pentark assess http://localhost:3000/ --output findings.json

# 4b. (Optional) A01 — Broken Access Control. Declare your authenticated
#     sessions under `identities:` in scope.yaml (see the template `init` writes),
#     capture a few authorized requests into a flows file, then replay them
#     across identities. Safe by default: only GET/HEAD/OPTIONS are ever sent.
pentark access --requests flows.yaml --forced-browsing http://localhost:3000/ -o access.json
#     Full method-tampering (actually sending PUT/DELETE) needs an explicit opt-in
#     and may modify data:
pentark access --requests flows.yaml --allow-mutation

# 5. Turn the findings into a professional report (Markdown and/or PDF).
pentark report findings.json --format both --output report
#    -> writes report.md and report.pdf

#    ...or do assess + report in one shot:
pentark assess http://localhost:3000/ -o findings.json --report report --report-format both

# 6. (Optional, authorized only) Offer Metasploit modules for the findings.
#    Default is SUGGESTIONS ONLY — nothing is sent to the target.
pentark exploit findings.json

#    Run a safe, non-destructive Metasploit check/scan (needs msfrpcd running,
#    started with a password you export as MSF_RPC_PASSWORD):
pentark exploit findings.json --check

#    Fire a REAL exploit for a confirmed finding — explicit, never automatic:
pentark exploit findings.json --run --unsafe --module exploit/<path>
```

The assessment prints a prioritized table (severity, CVSS, finding, confidence,
endpoint), writes the prioritized findings as JSON (which feeds reporting and
exploitation), and appends to the audit log. Its checks cover missing/weak
security headers, a safe reflected-XSS probe, and **A02 – Security
Misconfiguration**: exposed `.git/` / `.env` / backup / key files (confirmed by a
content signature, not a bare 200), directory listings, verbose error / stack
traces, technology-version disclosure, and the HTTP TRACE method. Testing a small
built-in **default-credential** list against a discovered login form is *active*
(it submits logins), so it is opt-in with `assess --default-creds`. It also covers
**A04 – Cryptographic Failures**: sensitive data / login forms over cleartext HTTP,
mixed content on HTTPS pages, **weak TLS** (obsolete protocols/ciphers, expired or
self-signed certificates — via a standard-library TLS handshake, no external
tools), API keys / tokens / private keys exposed in responses, JS, or URL query
strings (reported **masked**, never in the clear), and cookies missing
`Secure` / `HttpOnly` / `SameSite`. To assess a target behind an untrusted or
self-signed certificate, set `insecure_tls: true` under `settings:` in
`scope.yaml` — the weak-TLS check still reports the bad certificate. The `report` command reads that JSON
back and renders a cover, an executive summary with a severity breakdown, and a
detailed per-finding section (CVSS score + vector, confidence, CWE, endpoint,
description, evidence, remediation) plus a methodology/scope + disclaimer
appendix — as Markdown (`--format md`), PDF (`--format pdf`), or both.

The `access` command tests **A01 – Broken Access Control**. It replays each
request in a *flows file* under every authenticated identity from `scope.yaml`'s
`identities:` section (and with no session), flagging responses that return
privileged data to an identity that should not see it. It also runs **IDOR**
detection (mutating numeric/UUID identifiers and comparing responses), **forced
browsing** of admin paths, and **HTTP method tampering** (GET→PUT/DELETE). It is
non-destructive by default — only `GET`/`HEAD`/`OPTIONS` are ever sent, so IDOR
proves access purely by *reading* one unauthorized record; active method
tampering and replay of state-changing flows require the explicit
`--allow-mutation` opt-in. A flows file is a small YAML/JSON list:

```yaml
- name: my-account
  method: GET
  url: http://localhost:3000/account
  recorded_as: high        # which identity captured this request
- { method: GET, url: "http://localhost:3000/invoices/5", recorded_as: low }
```

The `logic` command tests **A06 – Insecure Design** (semi-automated). Because
design flaws can't be inferred from a URL, it is driven by a *logic spec*
(`--spec file.yaml`) in which you declare what to probe; it then reports **candidate
anomalies for manual review** (low confidence) and never auto-exploits them:
missing **rate limiting** on sensitive endpoints (burst requests, look for
throttling), **negative/overflow** values accepted by quantity/price fields,
**workflow step-skipping** (a later step reachable without the earlier ones), and
**race conditions** (concurrent requests where more succeed than should). A spec
looks like:

```yaml
rate_limit:
  - { name: login, url: "http://127.0.0.1:3000/login", body: { username: a, password: b }, attempts: 20 }
numeric_fields:
  - { name: cart, url: "http://127.0.0.1:3000/cart", field: quantity, extra: { item: "42" } }
workflows:
  - name: checkout
    protected_index: 2
    success_marker: "Order confirmed"
    steps: [ { url: ".../step1" }, { url: ".../step2" }, { url: ".../confirm" } ]
race:
  - { name: coupon, url: "http://127.0.0.1:3000/redeem", concurrency: 10, expected_success: 1 }
```

The `inject` command tests **A05 – Injection** (active). For each discovered
parameter (URL query + GET forms by default; POST forms with `--forms`) it tries
**SQLi** (error-based, and blind time-based `' AND SLEEP(n)` confirmed against a
zero-delay control), **OS command injection** (time-delay `; sleep n`), **SSTI**
(`{{269*271}}` / `${…}`, confirmed when `72899` appears and the expression does
not), and **XSS** (a unique canary reflected unescaped). Proof-of-concept is
deliberately **non-destructive**: it proves execution and at most reads a version
banner — it never dumps tables or modifies rows. Optional external confirmers are
off by default: `--sqlmap` (runs sqlmap with `--banner` only) and `--browser`
(Playwright confirms `alert(document.domain)` truly executes in the DOM). Point it
at `127.0.0.1` / a hostname rather than `localhost` to avoid a per-request IPv6
fallback delay.

The `components` command tests **A03 – Software Supply Chain Failures**
(detection only). It fingerprints JS libraries and frameworks from response
headers, `<script>` tags, inline version banners, `<meta generator>`, and — if
reachable — `package.json` / `package-lock.json`, then cross-references npm
components against the **OSV.dev** API and reports each vulnerable component with
its version, CVE IDs, and CVSS severity. Note the target is read through the
scope-gated client, but OSV.dev is queried through a **separate** client: it is a
third-party service we consult, not a target under test, so it is deliberately
not subject to the scope allowlist. Use `--no-osv` to fingerprint offline
without the CVE lookup.

The `exploit` command maps confirmed findings to candidate Metasploit modules and
**offers** them; by default it contacts nothing. `--check` runs Metasploit's
non-destructive `check()` (for exploit modules) or an auxiliary scanner; firing a
real exploit additionally requires `--run --unsafe` **and** an explicit per-module
confirmation. The target must be in scope, the authorization gate must pass, and
every step is audit-logged. Connecting to Metasploit is deferred until an active
action is actually requested.

---

## Architecture

```
src/pentark/
├── core/
│   ├── scope.py       # authorization gate + scope allowlist (default-deny)
│   ├── audit.py       # timestamped, append-only JSONL audit log
│   ├── ratelimit.py   # client-side request throttling
│   ├── banner.py      # consent/scope banner
│   └── errors.py      # typed exceptions
├── assess/
│   ├── cvss.py        # CVSS v3.1 base score + rating (pure, unit-tested)
│   ├── models.py      # Finding / AssessmentResult (severity from CVSS)
│   ├── http_client.py # scope + throttle + audit enforced on EVERY request
│   ├── checks/        # one module per vuln class (headers, reflected XSS,
│   │                  #   A02 misconfig: files/.git/.env, listings, TRACE, ...)
│   ├── access/        # A01 broken access control (multi-identity replay, IDOR,
│   │                  #   forced browsing, method tampering)
│   ├── supplychain/   # A03 component fingerprinting + OSV.dev CVE lookup
│   ├── crypto/        # A04 transport/TLS hygiene, secrets scan, cookie flags
│   ├── injection/     # A05 SQLi / XSS / command injection / SSTI (active)
│   ├── logic/         # A06 business-logic tests (rate limit, numeric, workflow, race)
│   └── runner.py      # orchestrate → dedupe → prioritize → JSON
├── report/
│   ├── markdown.py    # pure (result, meta) → Markdown report
│   └── pdf.py         # styled PDF via reportlab (optional 'report' extra)
├── exploit/
│   ├── mapping.py     # finding → candidate Metasploit modules (curated registry)
│   ├── msf.py         # msfrpcd client abstraction (pymetasploit3, optional 'exploit' extra)
│   └── session.py     # gate + scope + confirm + safe-mode + audit orchestration
├── preflight.py       # external-tool presence check
└── cli.py             # typer + rich CLI
```

Design principles: a **single scope choke point** (the HTTP client) so safety
can't be bypassed; **pure, testable cores** (CVSS, checks) with HTTP mocked in
tests; and **orchestration over reinvention** — later checks will parse the
structured output of sqlmap / nikto / nuclei rather than re-implement them.

## Development

```bash
python -m pytest            # runs fully offline (HTTP + tools mocked)
python -m pytest --cov
```

## License

MIT — see [LICENSE](LICENSE). Obtaining authorization to test any system is your
responsibility.
