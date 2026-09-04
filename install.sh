#!/usr/bin/env bash
# install.sh — installs the Tripwire kit into ~/.claude (macOS / Linux; Windows: Git Bash or WSL).
# What it does: copies the hooks, merges the hooks + deny rules into ~/.claude/settings.json
# (after backing it up), turns ~/.claude into a local git baseline, runs the integrity report.
# What it never does: add a git remote, call the network, or touch anything outside ~/.claude.
set -euo pipefail

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/kit" && pwd)"
CLAUDE="$HOME/.claude"
mkdir -p "$CLAUDE/hooks"

echo "1/4 hooks -> $CLAUDE/hooks"
cp "$KIT/guard-irreversible.py" "$KIT/guard-untrusted-data.py" "$KIT/integrity-report.sh" "$CLAUDE/hooks/"
chmod +x "$CLAUDE/hooks/guard-irreversible.py" "$CLAUDE/hooks/guard-untrusted-data.py" "$CLAUDE/hooks/integrity-report.sh"

echo "2/4 settings.json (backup first, then merge)"
if [ -f "$CLAUDE/settings.json" ]; then
  cp "$CLAUDE/settings.json" "$CLAUDE/settings.json.bak-$(date +%Y%m%d%H%M%S)"
fi
python3 - "$KIT/settings-hooks.json" "$CLAUDE/settings.json" <<'PYEOF'
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
add = json.load(open(src, encoding="utf-8"))
cur = json.load(open(dst, encoding="utf-8")) if os.path.exists(dst) else {}
hooks = cur.setdefault("hooks", {})
for event, entries in add["hooks"].items():
    have = hooks.setdefault(event, [])
    existing = {h.get("command") for e in have for h in e.get("hooks", [])}
    for e in entries:
        if not all(h.get("command") in existing for h in e["hooks"]):
            have.append(e)
perm = cur.setdefault("permissions", {})
deny = perm.setdefault("deny", [])
for rule in add.get("permissions", {}).get("deny", []):
    if rule not in deny:
        deny.append(rule)
json.dump(cur, open(dst, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print("   merged: hooks =", {k: len(v) for k, v in hooks.items()}, "| deny rules =", len(deny))
PYEOF

echo "3/4 git baseline in $CLAUDE (local only — never add a remote)"
if ! git -C "$CLAUDE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$CLAUDE" init -q
fi
cp "$KIT/gitignore-claude.txt" "$CLAUDE/.gitignore"
git -C "$CLAUDE" add -A
git -C "$CLAUDE" commit -qm "tripwire baseline $(date +%F)" >/dev/null 2>&1 || echo "   (nothing new to commit)"

echo "4/4 integrity report"
bash "$CLAUDE/hooks/integrity-report.sh" || true

cat <<'EOF'

Next:
  - Edit the CONFIG block at the top of ~/.claude/hooks/guard-irreversible.py
    (OWNER_EMAILS, ALLOWED_GIT_REMOTES, GATE_SECRET_READS), then: git -C ~/.claude commit -am "config"
  - Live test in a scratch folder: ask Claude to `mkdir tripwire-test && rm -rf tripwire-test`
    -> the rm must open an approval prompt naming the Tripwire.
  - Weekly: bash ~/.claude/hooks/integrity-report.sh
EOF
