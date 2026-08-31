# PentARK

A modular **Web Application Pentest Framework** for **authorized** security
testing, built as a study/portfolio project. It runs in three phases:

| Phase | What it does | Status |
|-------|--------------|--------|
| 1. **Assessment** | Scan a target web app, classify vulnerabilities, score them with **CVSS v3.1**, and output a **prioritized** findings list. | 🟢 in progress |
| 2. **Controlled exploitation** | *Optional, user-driven.* For confirmed findings, offer matching Metasploit modules via msfrpcd — never automatic. | ⛔ not started (by design) |
| 3. **Reporting** | Professional report (findings, CVSS, evidence, remediation) as Markdown + PDF. | ⛔ planned |

> **Current milestone:** the safety foundation (authorization gate, scope
> allowlist, audit log, rate limiting) plus the assessment phase for **missing
> security headers** and a **safe reflected-XSS** check, with CVSS scoring and
> prioritized JSON output. Exploitation is intentionally not implemented yet.

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
3. **No automatic exploitation.** Exploitation (a later phase) requires the
   target on the allowlist, an explicit per-finding confirmation, and a
   non-destructive **safe-mode** default.
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
python -m pip install -e ".[dev]"     # Python 3.11+
```

## Usage

```bash
# 1. Create your authorization/scope file and edit it.
cp scope.example.yaml scope.yaml
#    set authorized: true, operator, signed, and the hosts/url_prefixes you may test

# 2. Confirm the gate and see what's in scope.
pentark scope

# 3. Check optional external tools (used by later checks/phases).
pentark preflight

# 4. Run the assessment against an in-scope target.
pentark assess http://localhost:3000/ --output findings.json
```

The assessment prints a prioritized table (severity, CVSS, finding, confidence,
endpoint), writes the prioritized findings as JSON (which will feed reporting and
exploitation), and appends to the audit log.

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
