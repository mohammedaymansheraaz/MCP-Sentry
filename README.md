# MCP-Sentry
> Detection-only security auditor for Model Context Protocol servers.

MCP-Sentry inventories the exposed surface of an MCP server and flags security risks that are visible from the protocol layer. It is built for defensive review: it inspects tools, prompts, resources, transport metadata, and configuration, then turns that into a readable report.

It does not send exploit payloads, fuzz inputs, or mutate server state.

## Why It Exists

MCP servers often expose far more than a simple tool list. They expose schemas, descriptions, transport details, resource URIs, and metadata that can mislead an LLM or leave a server open to obvious mistakes. MCP-Sentry focuses on that visible surface because it is the fastest place to catch common issues before they become incidents.

It helps you answer questions like:

- Which tools accept unconstrained strings or paths?
- Which remote servers are exposed without authentication?
- Which tools look like SSRF, traversal, or command-injection shapes?
- Which descriptions are vague enough to confuse an agent?
- Did a configuration or description accidentally leak a secret?

## What You Get

| Output | What it gives you |
|---|---|
| `terminal` | A colored Rich report for quick triage in a shell |
| `markdown` | A shareable report you can commit, email, or archive |
| `json` | Machine-readable output for automation and dashboards |

The scan also produces a normalized server surface model that includes tools, prompts, resources, capabilities, transport details, and scan timestamp.

## Install

Requirements:

- Python 3.11 or newer
- `pip`
- `node` and `npx` if you want to run the bundled filesystem example server from `configs/example.yaml`

Recommended setup for local development:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

If you only want the CLI:

```bash
pip install -e .
```

## First Run

The repository ships with an example config that targets the official MCP filesystem server over `stdio`.

```bash
mcp-sentry scan --config configs/example.yaml --target filesystem
```

If you want to see the raw server surface without running any checks:

```bash
mcp-sentry scan --config configs/example.yaml --target filesystem --recon-only
```

If you want reports written to disk:

```bash
mcp-sentry scan --config configs/example.yaml --target filesystem --format markdown --output reports/filesystem_report.md
mcp-sentry scan --config configs/example.yaml --target filesystem --format json --output reports/filesystem_report.json
```

## Demo

Watch MCP-Sentry in action:

[![Demo Video](https://img.youtube.com/vi/YWgcnEZrF_8/0.jpg)](https://youtu.be/YWgcnEZrF_8)

## Setup Details

The example config uses a local filesystem server launched through `npx`:

```yaml
servers:
  filesystem:
    transport: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/tmp/mcp-sentry-test"
```

Create the target directory before scanning it:

```bash
mkdir -p /tmp/mcp-sentry-test
printf "hello\n" > /tmp/mcp-sentry-test/example.txt
```

If you are scanning a remote `streamable_http` server, the config can include headers and environment-variable interpolation:

```yaml
servers:
  remote:
    transport: streamable_http
    url: "https://example.com/mcp"
    headers:
      Authorization: "Bearer ${MCP_API_KEY}"
```

## How To Use It

### Scan a single server from config

```bash
mcp-sentry scan --config configs/example.yaml --target filesystem
```

Useful flags:

- `--format terminal|markdown|json` chooses how the report is rendered
- `--output <path>` writes Markdown or JSON to a file
- `--checks <id1,id2,...>` runs only selected checks
- `--recon-only` stops after enumeration and prints the surface as JSON
- `--verbose` enables more logging while connecting

Run only a subset of checks when you are focused on one class of issue:

```bash
mcp-sentry scan --config configs/example.yaml --target filesystem --checks PATH_TRAVERSAL,WEAK_AUTH
```

### Scan a one-off stdio command

```bash
mcp-sentry scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-sentry-test"
```

### Scan every server in a config file

```bash
mcp-sentry scan-all --config configs/example.yaml --output-dir reports
```

That command writes one Markdown report and one JSON report per server into the chosen directory.

## What the Checks Look For

| Check ID | Focus |
|---|---|
| `UNVALIDATED_INPUT` | Unconstrained strings, objects, and dangerous path or URL-shaped parameters |
| `WEAK_AUTH` | Missing auth on HTTP servers and suspicious hardcoded credentials in config |
| `SSRF_RISK` | Tools that accept URLs or network targets and appear to fetch remote content |
| `PATH_TRAVERSAL` | File-touching tools that accept unconstrained paths without clear sandbox boundaries |
| `HBV` | Hallucination-based vulnerabilities in tool descriptions and scope wording |
| `CREDENTIAL_LEAK` | Secrets accidentally embedded in descriptions, prompts, resources, or metadata |
| `TRANSPORT_SECURITY` | Insecure HTTP transport and other obvious transport-layer red flags |

These checks are static heuristics. They are designed to highlight risk, not prove exploitability.

## How Scoring Works

MCP-Sentry turns findings into a normalized score and a letter grade.

| Severity | Points |
|---|---|
| Critical | 25 |
| High | 15 |
| Medium | 5 |
| Low | 2 |
| Info | 0 |

The score is normalized by tool count so a server with many tools is not automatically punished just for having a larger surface. The grade bands are:

| Score | Grade |
|---|---|
| 0-2 | A |
| 3-7 | B |
| 8-15 | C |
| 16-25 | D |
| 26+ | F |

## Output Examples

The repository includes sample output generated from the filesystem reference server:

- `reports/filesystem_report.md`
- `reports/filesystem_report.json`

The report contains:

- a summary with the number of tools, prompts, resources, and findings
- the top findings with remediation guidance
- a full findings table
- a server-surface inventory
- a short methodology section

## Project Layout

```text
mcp_sentry/
  cli.py            CLI entry point and orchestration
  client.py         MCP session wrapper and surface enumeration
  config.py         YAML config loading and env interpolation
  models.py         Pydantic data models
  scanner.py        Check runner and report builder
  scoring.py        Score and grade calculation
  report.py         Terminal, Markdown, and JSON renderers
  checks/           Individual security checks
configs/
  example.yaml      Bundled filesystem example
reports/
  filesystem_report.md   Example Markdown report
  filesystem_report.json  Example JSON report
tests/
  ...               Unit tests and fixtures
```

## Limitations

- `streamable_http` transport is not fully implemented in the client wrapper yet.
- The tool is intentionally detection-only and does not attempt exploitation.
- Static checks can flag risk, but they cannot prove server-side enforcement or runtime leakage without active probing.

## Contributing

See `CONTRIBUTING.md` for development expectations and test guidance.
