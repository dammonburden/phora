# Phora

Phora is an AI-first binary analysis engine exposed through MCP. It loads binaries, extracts analysis facts, and packages binary context into tool responses that an LLM or harness can use for guided reverse-engineering workflows.

This is an early public source snapshot. It is useful for review, experimentation, and MCP integration work, but it is not a polished public release yet.

Phora is released under CC0 1.0 Universal. No rights are reserved. You may copy, modify, distribute, and use it for any purpose, including commercial use, without asking permission.

## Build

```sh
zig build
```

The release build is configured for a 2 MiB binary budget.

## Test

```sh
zig build test
zig build check-safe
zig build verify
```

Some integration tests inspect host-system binaries and may skip when expected local files are unavailable.

## Benchmark Harness

The dev-only MCP benchmark harness uses only the Python standard library and talks to Phora through `phora serve --stdio`.

```sh
python3 scripts/bench-phora.py --dry-run
python3 scripts/bench-phora.py --phora ./zig-out/bin/phora
python3 scripts/bench-phora.py --phora ./zig-out/bin/phora --case system-ls-auto-context --two-agent
```

Cases live in `benchmarks/cases.json`. Each case resolves the first available local target, skips cleanly when all target candidates are missing, records JSON validity, latency, MCP/tool errors, and scores expected clues in the returned analysis text.

Run reports are written by default under `benchmark-results/`, which is ignored and should remain untracked.

## MCP

Build Phora, then configure an MCP client with the stdio server:

```json
{
  "mcpServers": {
    "phora": {
      "command": "/absolute/path/to/phora/zig-out/bin/phora",
      "args": ["serve", "--stdio"]
    }
  }
}
```

Use `.mcp.example.json` as a template. Do not commit local `.mcp.json` files with machine-specific paths.

## License

Phora is dedicated to the public domain under [CC0 1.0 Universal](LICENSE). Where a public-domain dedication is not fully recognized, CC0 provides a broad fallback license.

## Known-Answer Benchmarks

The dev-only benchmark lane exercises Phora through MCP against local binaries and skips cases whose targets are missing:

```sh
scripts/bench-phora.py --dry-run
scripts/bench-phora.py --case phora-self-context
scripts/bench-phora.py --two-agent --case phora-self-context --case system-ls-auto-context
```

Benchmark results are written under `benchmark-results/` and are intentionally ignored.

## Safe Source Export

This working directory contains local reports, generated artifacts, and binary samples that should not be pushed. Use the guarded export path instead:

```sh
scripts/github-safe-publish.sh
```

The default mode creates a sanitized source-only export repository and does not push. Pushing requires an explicit remote, `--push`, and an explicit visibility confirmation flag: `--confirm-public-repo` or `--confirm-private-repo`.
