# Contributing to RieaZuka

Thanks for contributing.

1. Keep modules low-impact, bounded, and suitable for explicitly authorized targets.
2. Do not add brute force, credential theft, denial-of-service, destructive payloads, persistence, stealth/evasion, malware, or automated exploitation.
3. Add tests for new behavior.
4. Run `ruff check .` and `pytest` before submitting changes.
5. Never commit secrets, tokens, credentials, or real target data.

New checks should return structured `Finding` objects with clear evidence and remediation, minimize requests, honor exact scope, and use safe test fixtures or localhost services.
