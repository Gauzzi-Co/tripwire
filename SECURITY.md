# Security policy

AI Tripwire is a defense-in-depth kit. Bypasses are expected to exist — the point of reporting them is to close the ones that matter and to document the ones that cannot be closed by a hook.

## Reporting a bypass or vulnerability

Please **do not open a public issue** for a working bypass. Use GitHub's private vulnerability reporting on this repository (**Security → Report a vulnerability**). Include:

- the tool call or command text that got past a gate (or the content that should have raised an alarm and did not);
- which hook and which gate you expected to fire;
- your Claude Code version and OS.

You will get an acknowledgement within 5 business days. Fixes ship as a normal pull request with a test case reproducing the bypass; we credit reporters in the changelog unless they prefer otherwise.

## What is in scope

- A command that sends data out, deletes, or modifies protected files without an `ask`/`deny` decision from `guard-irreversible.py`.
- Third-party content that reaches the model without the fence from `guard-untrusted-data.py`.
- A way to make either hook fail *silently* (they are designed to fail closed).
- Hidden-content techniques that `scan-instructions.sh` does not flag.

## What is out of scope

- Obfuscation that requires the user to have already approved an arbitrary command (the kit is explicit that regex gates are a boundary, not a proof).
- Vulnerabilities in Claude Code itself or in third-party MCP servers — report those to their maintainers.
