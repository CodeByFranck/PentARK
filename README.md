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
exploitation), and appends to the audit log. The `report` command reads that JSON
back and renders a cover, an executive summary with a severity breakdown, and a
detailed per-finding section (CVSS score + vector, confidence, CWE, endpoint,
description, evidence, remediation) plus a methodology/scope + disclaimer
appendix — as Markdown (`--format md`), PDF (`--format pdf`), or both.

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
│   ├── checks/        # one module per vuln class (headers, reflected XSS, ...)
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
