# Contributing

Thanks for helping make AI agents harder to hijack. A few house rules keep this kit trustworthy — it runs on every tool call of everyone who installs it.

## Ground rules

- **Fail closed.** Any change to a hook must keep the property that a crash or unparseable input produces an `ask` (or a loud notice), never a silent allow. The fail-closed self-test in `integrity-report.sh` must still pass.
- **No network, no writes.** Hooks and the scanner read and decide; they never call out and never modify files other than their own log (`~/.claude/fence-alarms.log`) and the scan report. Keep it that way.
- **Every gate ships with a test.** Add a case to `tests/test_hooks.py` for each new gate or signature (both kits if the change applies to both).
- **No literal invisible characters** in source files — the scanner would flag the kit itself. Use `\uXXXX` escapes (there is a check for this in CI).
- **Bilingual signatures.** New signatures should cover English and Portuguese where a natural equivalent exists; other languages welcome.
- **Keep the two editions in sync.** `kit/` (English) and `kit-pt-BR/` differ only in user-facing strings and comments.

## Workflow

1. Fork, branch from `main`.
2. `pip install ruff pytest` · `ruff check . && ruff format --check .` · `pytest -q` · `shellcheck kit/*.sh kit-pt-BR/*.sh install.sh`.
3. Open a PR describing the attack or gap the change addresses. CI runs lint, tests, dependency review and an AI review; all must be green.

## Reporting a bypass

See [SECURITY.md](SECURITY.md) — please report working bypasses privately.
