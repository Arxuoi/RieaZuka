# RieaZuka

RieaZuka is an open-source, cross-platform **authorized web security auditing agent** for Windows, Linux, Ubuntu, and macOS.

It performs low-impact security checks and produces actionable JSON/HTML reports. It is designed for systems you own or have explicit permission to test.

## Features

- Strict target/scope validation and authorization acknowledgement
- HTTP security header audit
- Cookie flag audit (`Secure`, `HttpOnly`, `SameSite`)
- CORS policy inspection using a benign origin
- TLS certificate/version inspection
- Basic technology disclosure detection
- `security.txt` and `robots.txt` discovery
- JSON and self-contained HTML reports
- Cross-platform Python CLI
- Rate-limited requests and bounded timeouts
- Extensible module interface

RieaZuka intentionally does **not** include brute force, credential attacks, exploit payloads, persistence, evasion, destructive scanning, denial-of-service, or automated exploitation.

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/Arxuoi/RieaZuka.git
cd RieaZuka
python -m pip install -e .
```

## Usage

Local lab target:

```bash
rieazuka scan http://localhost:8000 --scope localhost
```

Authorized HTTPS target:

```bash
rieazuka scan https://app.example.test --scope app.example.test --ack-authorized --json report.json --html report.html
```

Select modules:

```bash
rieazuka scan https://app.example.test --scope app.example.test --ack-authorized --modules headers,cookies,cors,tls,tech,security-txt,robots
```

Other commands:

```bash
rieazuka modules
rieazuka version
```

## Authorization model

For non-local targets, RieaZuka requires both an explicit `--scope` and `--ack-authorized`. Scope is default-deny: redirects leaving the permitted hostname are rejected. Authorization remains the operator's responsibility.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
```

## License

MIT. See `LICENSE`.

## Security

Please read `SECURITY.md` before reporting a vulnerability or using RieaZuka in a security assessment.
