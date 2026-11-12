## Consolidated Findings Table

| ID | Vulnerability / Finding | LLM A | LLM B | LLM C | Bandit | Semgrep |
|---|---|:---:|:---:|:---:|:---:|:---:|
| F1 | Path traversal / arbitrary file read (`/files`) | ✓ | ✓ | ✓ | — | — |
| F2 | Missing authentication and authorisation on grade updates | ✓ | ✓ | ✓ | — | — |
| F3 | Broken Object Level Authorization (BOLA) on student profiles and grades | ✓ | ✓ | ✓ | — | — |
| F4 | Hardcoded Flask secret key | ✓ | ✓ | — | ✓ | — |
| F5 | Verbose error disclosure / information disclosure | ✓ | ✓ | ✓ | — | — |
| F6 | Flask debug mode enabled | ✓ | ✓ | — | ✓ | ✓ |
| F7 | Application bound to all network interfaces (`0.0.0.0`) | — | — | — | ✓ | ✓ |
| F8 | Missing authentication on protected endpoints | — | — | ✓ | — | — |
| F9 | Insufficient input validation on grade updates | — | — | ✓ | — | — |
| F10 | Hardcoded plaintext user passwords | — | — | — | ✓ | — | 

### Static Analysis Results

| Tool | Version | Total Findings | High | Medium | Low | Warning |
|---|---|---:|---:|---:|---:|---:|
| Bandit | 1.9.4 | 7 | 1 | 1 | 5 | — |
| Semgrep | 1.183.0 | 2 | — | — | — | 2 |

### Tool Environment

| Component | Version |
|---|---|
| Python | 3.10.22 |
| Bandit | 1.9.4 |
| Semgrep | 1.183.0 |

**Legend:** ✓ = Finding identified by the tool; — = Finding not identified by the tool.