#!/usr/bin/env bash
# install.sh — installs the AI Tripwire kit into ~/.claude (macOS / Linux; Windows: Git Bash or WSL).
#
# What it does:  copies the hooks + the interpreter wrapper, writes ~/.claude/tripwire.json ONCE (your
#                config: owner e-mails, allowed git remotes) and never overwrites it on upgrades, merges
#                the hooks + deny rules into ~/.claude/settings.json (backup first), creates a LOCAL git
#                baseline in ~/.claude — only if ~/.claude is not already inside another repository —
#                and runs the integrity report.
# What it never does: add a git remote, call the network, commit into a repository it did not create,
#                or touch anything outside ~/.claude.
set -euo pipefail

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/kit" && pwd)"
CLAUDE="$HOME/.claude"
HOOKS="$CLAUDE/hooks"
CONFIG="$CLAUDE/tripwire.json"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "ERROR: python3 (or python) is required — install it first, nothing was changed." >&2
  exit 1
fi
mkdir -p "$HOOKS"

echo "1/5 hooks -> $HOOKS"
cp "$KIT/guard-irreversible.py" "$KIT/guard-untrusted-data.py" "$KIT/integrity-report.sh" "$KIT/tripwire-run.sh" "$HOOKS/"
chmod +x "$HOOKS/guard-irreversible.py" "$HOOKS/guard-untrusted-data.py" "$HOOKS/integrity-report.sh" "$HOOKS/tripwire-run.sh"
# the alarm log is evidence: create it now so the baseline tracks it from day one
[ -f "$CLAUDE/fence-alarms.log" ] || touch "$CLAUDE/fence-alarms.log"

echo "2/5 config -> $CONFIG"
if [ -f "$CONFIG" ]; then
  echo "   exists — kept as is (edit it by hand; upgrades never overwrite it)"
else
  cp "$KIT/tripwire.json" "$CONFIG"
  echo "   created from template — EDIT IT NOW: owner_emails, allowed_git_remotes"
fi

echo "3/5 settings.json (backup first, then merge)"
if [ -f "$CLAUDE/settings.json" ]; then
  cp "$CLAUDE/settings.json" "$CLAUDE/settings.json.bak-$(date +%Y%m%d%H%M%S)"
fi
"$PY" - "$KIT/settings-hooks.json" "$CLAUDE/settings.json" <<'PYEOF'
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
add = json.load(open(src, encoding="utf-8"))
try:
    cur = json.load(open(dst, encoding="utf-8")) if os.path.exists(dst) else {}
except json.JSONDecodeError as e:
    sys.exit(f"   ERROR: {dst} is not valid JSON ({e}). Fix it (a backup was made) and re-run.")
if not isinstance(cur, dict):
    sys.exit(f"   ERROR: {dst} must contain a JSON object at the top level.")
hooks = cur.get("hooks")
if not isinstance(hooks, dict):
    hooks = {}
    cur["hooks"] = hooks
for event, entries in add["hooks"].items():
    have = hooks.get(event)
    if not isinstance(have, list):
        have = []
        hooks[event] = have
    existing = {h.get("command") for e in have if isinstance(e, dict) for h in e.get("hooks", []) if isinstance(h, dict)}
    for e in entries:
        if not all(h.get("command") in existing for h in e["hooks"]):
            have.append(e)
perm = cur.get("permissions")
if not isinstance(perm, dict):
    perm = {}
    cur["permissions"] = perm
deny = perm.get("deny")
if not isinstance(deny, list):
    deny = []
    perm["deny"] = deny
for rule in add.get("permissions", {}).get("deny", []):
    if rule not in deny:
        deny.append(rule)
json.dump(cur, open(dst, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print("   merged: hooks =", {k: len(v) for k, v in hooks.items()}, "| deny rules =", len(deny))
PYEOF

echo "4/5 git baseline in $CLAUDE (local only — never add a remote)"
TOP="$(git -C "$CLAUDE" rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "$TOP" ] && [ "$TOP" != "$(cd "$CLAUDE" && pwd -P)" ]; then
  echo "   SKIPPED: $CLAUDE is inside another git repository ($TOP) — committing there could push your"
  echo "   hooks and settings to that repository's remote. Add ~/.claude to that repo's .gitignore, or"
  echo "   keep the baseline by hand: cd ~/.claude && git init && cp $KIT/gitignore-claude.txt .gitignore"
elif [ -n "$TOP" ] && [ -n "$(git -C "$CLAUDE" remote 2>/dev/null)" ]; then
  echo "   SKIPPED: $CLAUDE already has a git remote configured — the baseline must stay local. Remove the"
  echo "   remote (git -C ~/.claude remote remove <name>) if you want Tripwire to commit here."
else
  if [ -z "$TOP" ]; then
    git -C "$CLAUDE" init -q
  fi
  cp "$KIT/gitignore-claude.txt" "$CLAUDE/.gitignore"
  git -C "$CLAUDE" add -A
  if git -C "$CLAUDE" -c user.name="tripwire" -c user.email="tripwire@localhost" commit -qm "tripwire baseline $(date +%F)"; then
    echo "   committed baseline"
  else
    echo "   nothing new to commit"
  fi
fi

echo "5/5 integrity report"
bash "$HOOKS/integrity-report.sh" || true

cat <<EOF

Next:
  - Edit $CONFIG: "owner_emails" (mail to yourself passes silently) and "allowed_git_remotes" (regex).
  - Optional hardening: chmod 444 $HOOKS/*.py   (macOS: chflags uchg $HOOKS/*.py)
    and make the alarm log append-only (macOS: chflags uappnd $CLAUDE/fence-alarms.log — undo with nouappnd)
  - Live test in a scratch folder: ask Claude to \`mkdir tripwire-test && rm -rf tripwire-test\`
    -> the rm must open an approval prompt naming the Tripwire.
  - Weekly: bash $HOOKS/integrity-report.sh
EOF
