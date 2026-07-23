# Contributing

MCP-Sentry is a detection-only security tool. Contributions must stay within defensive analysis, reporting, and validation of exposed MCP metadata.

## Expectations

- Keep changes ASCII unless the file already uses other characters.
- Prefer small, reviewable patches with tests.
- Do not add exploit payloads, fuzzers, or destructive probes.
- Update documentation when behavior changes.

## Local Development

```bash
pip install -e .[dev]
pytest -q
```

## Test Focus

- Model serialization and config loading
- Check logic for the static heuristics
- Scanner orchestration and report rendering
- CLI smoke coverage when practical

## Security Posture

- Preserve the detection-only statement in user-facing docs.
- Redact secrets in findings and reports.
- Treat transport, auth, and filesystem handling conservatively.
