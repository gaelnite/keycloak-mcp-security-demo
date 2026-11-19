# Contributing

This project maintains an experimental MCP security reference. Start with the
[showcase](README.md) and its [security model](docs/SECURITY.md). Report a
suspected vulnerability through the [security policy](SECURITY.md).

Open an issue for a change larger than a typo or a single-file fix. Submit a
focused pull request on a `feat/`, `fix/`, `docs/`, `chore/`, `refactor/` or
`test/` branch. The maintainer reviews and manually merges PRs to `main`.
Resolve review conversations and wait for `ci-gate` and `docker-gate` to pass.
GitHub requires a PR for changes to `main`.

## Run the local checks

Use Python 3.11 or later and Node.js 22 from the repository root.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r mcp/requirements.txt
npm ci --prefix mcp
.venv/bin/python -m unittest discover -s tests -t . -v
echo '{"op":"validate"}' | node mcp/pdp.mjs
.venv/bin/python mcp/gen_cedar.py --check
.venv/bin/python mcp/gen_tool_wrappers.py --check
```

The unit suite uses the real Cedar engine. Docker CI builds and verifies the
headless, interactive, and delegated profiles on every PR to `main`, including
docs-only changes.
[CI workflows](.github/workflows) · [Docker demo](docs/DOCKER.md)

## What to include in a change

- Describe the profile, version, checks run and any skips. For a security
  change, show both the permitted operation and the corresponding denial.
- Cite the protocol revision and section for changes to protocol behavior.
  Keep the verified human subject, desktop client and attested workload distinct.
- Keep Markdown files at or below 150 lines. Use synthetic identities in examples.
  Keep credentials, approval tokens, private host information
  and raw session transcripts out of commits, issues and CI logs.

Contributions are licensed under [Apache 2.0](LICENSE).
