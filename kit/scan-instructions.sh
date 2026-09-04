#!/usr/bin/env bash
# scan-instructions.sh — Poisoned instruction & memory scan
# Tripwire Protocol · Gauzzi & Co · client edition v1.0
#
# WHAT IT DOES: inventories EVERY file that gives persistent instructions to your
# AI assistant (CLAUDE.md, memories, agents, skills, hooks, settings, MCP configs),
# searches them for known prompt-injection signatures, audits permissions/hooks/MCP
# configuration, checks for persistence outside Claude (cron, shell rc files, git
# hooks, ssh) and sweeps session transcripts for exfiltration commands.
#
# WHAT IT DOES NOT DO: no LLM, no modifications, nothing sent anywhere. It only reads
# and writes a report to ~/security-scan/. Deterministic — an attacker cannot "talk"
# this script into anything.
#
# USAGE:  bash scan-instructions.sh                 # scans $HOME (depth 8)
#         bash scan-instructions.sh /other/folder   # extra folders
#         SCAN_MAXDEPTH=12 bash scan-instructions.sh
# Windows: run in Git Bash or WSL (home is %USERPROFILE%).
# Synced cloud folders (Drive/OneDrive/iCloud): reading may download "online-only"
# files — accept it, or exclude the path via EXCLUDE_EXTRA='pattern'.
set -uo pipefail

OUT_DIR="$HOME/security-scan"; mkdir -p "$OUT_DIR"
STAMP="$(date +%Y-%m-%d_%H%M)"
REPORT="$OUT_DIR/report-$STAMP.txt"
LIST="$OUT_DIR/files-$STAMP.txt"
MAXDEPTH="${SCAN_MAXDEPTH:-8}"
EXCLUDE_EXTRA="${EXCLUDE_EXTRA:-__none__}"
: > "$REPORT"; : > "$LIST"

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
hdr() { log ""; log "================================================================"; log "$*"; log "================================================================"; }

hdr "TRIPWIRE SCAN — $(date '+%Y-%m-%d %H:%M %Z') — host: $(hostname) — user: $(whoami)"
log "Report: $REPORT"
log "Inventory: $LIST"

# ---------------------------------------------------------------- A. INVENTORY
hdr "A. INVENTORY — files that instruct the AI (most recently modified first)"
PRUNE=( -path '*/node_modules' -o -path '*/.Trash' -o -path '*/Library/Caches' -o -path '*/Library/Containers' \
        -o -path '*/.npm' -o -path '*/.cache' -o -path '*/.cargo' -o -path '*/.rustup' -o -path '*/site-packages' \
        -o -path '*/.venv' -o -path '*/venv' -o -path '*/.git/objects' -o -path '*/Library/Application Support/Google' )

{
  # 1) instruction files of any AI tool, anywhere under home
  find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type f \( \
       -name 'CLAUDE.md' -o -name 'CLAUDE.local.md' -o -name 'MEMORY.md' -o -name 'HANDOFF.md' \
       -o -name 'AGENTS.md' -o -name 'GEMINI.md' -o -name '.cursorrules' -o -name '.windsurfrules' \
       -o -name 'copilot-instructions.md' -o -name 'SKILL.md' -o -name '.mcp.json' \
       -o -name 'claude_desktop_config.json' -o \( -name '*.mdc' -path '*/.cursor/rules/*' \) \
       -o \( -name '*.md' -path '*/.claude/rules/*' \) \) -print 2>/dev/null
  # 2) everything inside .claude directories (global and per-project): agents, commands, skills, hooks, memory, settings
  find "$HOME/.claude" -maxdepth 6 -type f \( -name '*.md' -o -name '*.json' -o -name '*.py' -o -name '*.sh' -o -name '*.js' -o -name '*.ts' \) \
       -not -path '*/projects/*/*.jsonl' -not -path '*/cache/*' -not -path '*/shell-snapshots/*' -not -path '*/file-history/*' \
       -not -path '*/paste-cache/*' -not -path '*/telemetry/*' -not -path '*/uploads/*' -not -path '*/sessions/*' -not -path '*/tool-results/*' -not -path '*/workflows/*' -not -path '*/subagents/*' -print 2>/dev/null
  find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type d -name '.claude' -not -path "$HOME/.claude" -print 2>/dev/null \
    | while IFS= read -r d; do find "$d" -maxdepth 4 -type f \( -name '*.md' -o -name '*.json' -o -name '*.py' -o -name '*.sh' -o -name '*.js' \) -print 2>/dev/null; done
  # 3) user-level configs
  for f in "$HOME/.claude.json" "$HOME/.codex/config.toml" "$HOME/.codex/instructions.md" "$HOME/.gemini/settings.json" \
           "$HOME/Library/Application Support/Claude/claude_desktop_config.json" "$APPDATA/Claude/claude_desktop_config.json"; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
} 2>/dev/null | grep -v -E "$EXCLUDE_EXTRA" | sort -u > "$LIST"

TOTAL=$(wc -l < "$LIST" | tr -d ' ')
log "Files found: $TOTAL"
log ""
log "  MODIFIED             SIZE     SHA256(12)     PATH"
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f" >/dev/null 2>&1; then mt=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f"); sz=$(stat -f '%z' "$f");
  else mt=$(stat -c '%y' "$f" | cut -c1-16); sz=$(stat -c '%s' "$f"); fi
  sha=$(shasum -a 256 "$f" 2>/dev/null | cut -c1-12)
  printf '  %s  %7s  %s   %s\n' "$mt" "$sz" "$sha" "$f"
done < "$LIST" | sort -r | tee -a "$REPORT" >/dev/null
log ""
log "  ^ Recent modifications YOU don't recognize are the first signal."

# ---------------------------------------------------- B. SIGNATURES + HIDDEN CONTENT
hdr "B. PROMPT-INJECTION SIGNATURES + HIDDEN CONTENT (per file:line)"
python3 - "$LIST" <<'PYEOF' | tee -a "$REPORT"
import sys, re, os
files = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8", errors="replace") if l.strip()]
# Signatures are bilingual (EN + PT-BR) on purpose: injections arrive in either language.
SIGS = [
 ("SECRECY / hide from the user",
  re.compile(r"(never|do not|don'?t|nunca|n[ãa]o)\s+(tell|alert|inform|notify|mention|reveal|disclose|show|display|conte|avise|informe|mencione|revele|mostre)\b.{0,50}\b(user|owner|human|operator|usu[áa]rio|dono|ele|ela|voc[êe])|"
             r"(conceal|hide|keep\s+(this|it)\s+(secret|hidden|private)|secretly|silently|without\s+(telling|informing|asking|notifying)|"
             r"oculte|esconda|em\s+segredo|sem\s+(avisar|informar|perguntar)|n[ãa]o\s+(mencione|revele|mostre)\s+(isso|isto|esta|este))", re.I)),
 ("OVERRIDE / reframing",
  re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)|disregard\s+(all\s+)?(previous|prior)|you\s+are\s+now|new\s+instructions|"
             r"system\s+prompt|developer\s+message|from\s+now\s+on\s+(always|never)|desconsidere\s+(as\s+)?(instru[çc][õo]es|regras)|"
             r"ignore\s+(as\s+)?instru[çc][õo]es\s+anteriores|voc[êe]\s+agora\s+[ée]|novas\s+instru[çc][õo]es", re.I)),
 ("AUTO-APPROVAL / no permission",
  re.compile(r"(always|automatically|sempre|automaticamente)\s+(approve|allow|accept|run|execute|aprove|permita|aceite|execute)|"
             r"without\s+(confirmation|permission|approval)|do\s+not\s+ask\s+(for\s+)?(permission|confirmation)|"
             r"n[ãa]o\s+pe[çc]a\s+(permiss[ãa]o|confirma[çc][ãa]o)|dangerously-skip-permissions|bypasspermissions", re.I)),
 ("EXFILTRATION / send outward",
  re.compile(r"(send|post|upload|forward|transmit|exfil|sync|mirror|envie|poste|suba|encaminhe|transmita|sincronize)\b.{0,60}\b(to|para)\b.{0,60}(https?://|@|webhook|endpoint|server|bucket|api)|"
             r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok\.(io|app|dev)|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|requestbin|pipedream\.net|burpcollaborator|oastify\.com|interact\.sh", re.I)),
 ("SECRET HARVESTING",
  re.compile(r"(collect|gather|read|copy|include|extract|colete|leia|copie|inclua|extraia)\b.{0,50}\b(api[_ -]?keys?|tokens?|passwords?|secrets?|credentials?|\.env\b|id_rsa|id_ed25519|private\s+key|senhas?|credenciais|chaves?\s+(de\s+)?api)", re.I)),
 ("PERSISTENCE / write to memory",
  re.compile(r"(remember|save|store|add|write|persist|memorize|lembre|salve|guarde|adicione|grave)\b.{0,40}\b(to|in|into|em|no|na)\b.{0,30}(memory|mem[óo]ria|CLAUDE\.md|MEMORY\.md|settings|hooks?)", re.I)),
 ("GUARDRAIL SABOTAGE",
  re.compile(r"(disable|remove|delete|comment\s+out|bypass|skip|desative|remova|apague|comente|contorne|pule)\b.{0,40}\b(hooks?|guards?|guardrails?|safety|checks?|tests?|lint|verifica[çc][õo]es|seguran[çc]a)", re.I)),
 ("AI-DIRECTED IMPERATIVE",
  re.compile(r"\b(assistant|claude|ai|agent|copilot|assistente|agente)\b[^.\n]{0,40}\b(must|should|will|deve|precisa)\s+(run|execute|send|forward|delete|download|install|approve|executar|enviar|encaminhar|apagar|baixar|instalar|aprovar)\b", re.I)),
]
ZW = re.compile("[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]")  # zero-width, bidi, BOM, soft hyphen (escapes: this file contains none of them)
B64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
HTMLC = re.compile(r"<!--.*?-->", re.S)
hits = 0; hidden = 0
for f in files:
    try:
        if os.path.getsize(f) > 5_000_000: print(f"  [skipped >5MB] {f}"); continue
        text = open(f, encoding="utf-8", errors="replace").read()
    except Exception as e:
        print(f"  [read error] {f}: {e}"); continue
    for i, line in enumerate(text.splitlines(), 1):
        for label, rx in SIGS:
            m = rx.search(line)
            if m:
                hits += 1
                snip = line.strip()[:220]
                print(f"  [{label}] {f}:{i}\n      {snip}")
    zw = ZW.findall(text)
    if zw:
        hidden += 1; print(f"  [HIDDEN: {len(zw)} invisible/bidi character(s)] {f}  <- invisible to humans, readable by the AI")
    for m in HTMLC.finditer(text):
        body = m.group(0)
        if len(body) > 60 and f.lower().endswith((".md", ".mdc", ".txt")):
            hidden += 1; print(f"  [HIDDEN: HTML comment inside markdown, {len(body)} chars] {f}\n      {body[:200].replace(chr(10),' ')}")
    if B64.search(text) and not f.endswith((".json", ".jsonl", ".png", ".svg")):
        hidden += 1; print(f"  [HIDDEN: long base64 blob] {f}")
    longl = [i for i, l in enumerate(text.splitlines(), 1) if (re.search(r"[ \t]{60,}\S", l) or len(l) > 3000) and f.lower().endswith((".md", ".mdc", ".txt"))]
    if longl:
        hidden += 1; print(f"  [HIDDEN: line(s) with whitespace padding or >3000 chars — can hide instructions off-screen] {f}: lines {longl[:5]}")
print(f"\n  TOTAL: {hits} textual signature(s), {hidden} hidden-content indicator(s).")
print("  False positives are expected (e.g. a security hook QUOTES the very signatures). Review each one in Phase 2.")
PYEOF

# ----------------------------------------------------------- C. CONFIG / HOOKS / MCP
hdr "C. CONFIGURATION AUDIT — permissions, hooks, MCP servers, plugins"
python3 - "$LIST" <<'PYEOF' | tee -a "$REPORT"
import sys, json, os, re, hashlib, glob
home = os.path.expanduser("~")
files = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8", errors="replace") if l.strip()]
def load(p):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception as e: return {"__error__": str(e)}
def sha(p):
    try: return hashlib.sha256(open(p,"rb").read()).hexdigest()[:12]
    except Exception: return "?"
settings = [p for p in files if re.search(r"/\.claude/settings(\.local)?\.json$", p)]
for p in settings:
    d = load(p); print(f"\n  SETTINGS: {p}")
    perm = d.get("permissions", {}) if isinstance(d, dict) else {}
    print(f"    defaultMode: {perm.get('defaultMode', '(default)')}")
    for k in ("allow", "deny", "ask"):
        v = perm.get(k) or []
        if v: print(f"    permissions.{k} ({len(v)}): " + "; ".join(map(str, v))[:900])
    broad = [r for r in (perm.get("allow") or []) if re.search(r"Bash\(\*?\)|Bash\(\*\)|^Bash$|curl|wget|scp|rclone|\brm\b", str(r))]
    if broad: print(f"    !! BROAD ALLOW (review): {broad}")
    hooks = d.get("hooks", {}) if isinstance(d, dict) else {}
    for ev, entries in hooks.items():
        for e in entries or []:
            for h in e.get("hooks", []):
                cmd = h.get("command", "")
                print(f"    HOOK {ev} [{e.get('matcher','*')}]: {cmd}")
                for path in re.findall(r"(\S+\.(?:py|sh|js|ts|rb|pl))", cmd):
                    path = os.path.expandvars(path.replace("$HOME", home).replace("~", home)).strip('"\'')
                    if os.path.exists(path):
                        head = open(path, encoding="utf-8", errors="replace").read(400).replace("\n", " | ")
                        print(f"      -> {path}  sha256:{sha(path)}\n         head: {head[:300]}")
                    else:
                        print(f"      -> !! HOOK FILE DOES NOT EXIST: {path}")
                if re.search(r"curl|wget|nc |base64|python -c|eval|\$\(", cmd) and not re.search(r"\.(py|sh|js)\b", cmd):
                    print("      !! INLINE HOOK with network/eval — every hook runs on EVERY tool call: read it carefully")
cj = os.path.join(home, ".claude.json")
if os.path.exists(cj):
    d = load(cj); print(f"\n  USER CONFIG: {cj}")
    def show_mcp(servers, scope):
        for name, cfg in (servers or {}).items():
            tgt = cfg.get("command") or cfg.get("url") or cfg.get("httpUrl") or ""
            args = " ".join(map(str, cfg.get("args", [])))
            print(f"    MCP [{scope}] {name}: {tgt} {args}"[:300])
    show_mcp(d.get("mcpServers"), "user")
    for proj, pd in (d.get("projects") or {}).items():
        if isinstance(pd, dict) and pd.get("mcpServers"): show_mcp(pd["mcpServers"], f"project {proj}")
        if isinstance(pd, dict) and pd.get("allowedTools"): print(f"    allowedTools [{proj}]: {pd['allowedTools']}"[:400])
for p in files:
    if p.endswith((".mcp.json", "claude_desktop_config.json")):
        d = load(p); print(f"\n  MCP FILE: {p}")
        for name, cfg in (d.get("mcpServers") or {}).items():
            print(f"    MCP {name}: {cfg.get('command') or cfg.get('url')} {' '.join(map(str, cfg.get('args', [])))}"[:300])
plug = os.path.join(home, ".claude", "plugins")
if os.path.isdir(plug):
    print(f"\n  PLUGINS in {plug}:")
    for root in sorted(glob.glob(os.path.join(plug, "*"))): print(f"    {root}")
print("\n  Review: every MCP/plugin/hook you did NOT consciously install is suspect. Hooks execute code on every tool call.")
PYEOF

# ------------------------------------------------- D. PERSISTENCE OUTSIDE CLAUDE
hdr "D. PERSISTENCE OUTSIDE CLAUDE — cron, launch agents, shell rc, git, ssh, binary"
log "-- The 'claude' binary (an alias/wrapper in front of the real binary is a vector) --"
type claude 2>&1 | head -3 | tee -a "$REPORT" >/dev/null
command -v -a claude 2>/dev/null | tee -a "$REPORT" >/dev/null
log "-- crontab --"; (crontab -l 2>/dev/null || echo "  (empty)") | tee -a "$REPORT" >/dev/null
if [ -d "$HOME/Library/LaunchAgents" ]; then
  log "-- LaunchAgents (macOS) --"
  for f in "$HOME"/Library/LaunchAgents/*.plist; do [ -f "$f" ] && log "  $f" && grep -A3 -i "ProgramArguments" "$f" 2>/dev/null | grep -o "<string>.*</string>" | head -4 | sed 's/^/      /' | tee -a "$REPORT" >/dev/null; done
fi
[ -d "$HOME/.config/systemd/user" ] && { log "-- systemd user units --"; ls -la "$HOME/.config/systemd/user" | tee -a "$REPORT" >/dev/null; }
log "-- Shell rc files (suspicious lines: network, base64, eval, claude alias) --"
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [ -f "$f" ] || continue
  mt=$(stat -f '%Sm' -t '%Y-%m-%d' "$f" 2>/dev/null || stat -c '%y' "$f" | cut -c1-10)
  log "  $f (modified $mt)"
  grep -nE 'curl|wget|base64|eval |nc |/dev/tcp|python[3]? -c|alias claude=|claude\(\)|PROMPT_COMMAND|precmd' "$f" 2>/dev/null | sed 's/^/      /' | tee -a "$REPORT" >/dev/null
done
log "-- Global git config (hooksPath/templateDir/includes are silent-execution vectors) --"
git config --global --list 2>/dev/null | grep -iE 'hookspath|templatedir|include|credential|url\.' | sed 's/^/  /' | tee -a "$REPORT" >/dev/null || log "  (none)"
log "-- SSH --"
[ -f "$HOME/.ssh/authorized_keys" ] && log "  authorized_keys: $(wc -l < "$HOME/.ssh/authorized_keys" | tr -d ' ') key(s), modified $(stat -f '%Sm' -t '%Y-%m-%d' "$HOME/.ssh/authorized_keys" 2>/dev/null || stat -c '%y' "$HOME/.ssh/authorized_keys" | cut -c1-10)"
[ -f "$HOME/.ssh/config" ] && grep -nE 'ProxyCommand|LocalCommand|PermitLocalCommand' "$HOME/.ssh/config" 2>/dev/null | sed 's/^/  ssh config: /' | tee -a "$REPORT" >/dev/null
log "-- Git remotes of every repository (a remote you don't recognize = exfiltration by push) --"
find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type d -name '.git' -print 2>/dev/null | while IFS= read -r g; do
  r="$(dirname "$g")"; git -C "$r" remote -v 2>/dev/null | awk -v repo="$r" '/\(push\)/{print "  " $2 "   <- " repo}'
done | sort -u | tee -a "$REPORT" >/dev/null

# ------------------------------------------------- E. SESSION FORENSICS
hdr "E. SESSION FORENSICS — exfiltration commands executed in the last 60 days"
PAT='curl [^"]*(-d |--data|-F |-T |--upload-file|-X POST|-X PUT|--json)|wget [^"]*--post|gws gmail \+(send|reply|forward)|\bscp |\brsync [^"]*@|\brclone (copy|sync|move)|aws s3 (cp|sync)|gsutil (cp|rsync)|webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|dangerously-skip-permissions|base64 [^"]*\| *curl|/dev/tcp/'
log "  (this section greps every transcript of the last 60 days; on a heavy machine it can take several minutes — transcripts over 80 MB are skipped and listed)"
if [ -d "$HOME/.claude/projects" ]; then
  find "$HOME/.claude/projects" -name '*.jsonl' -mtime -60 -size +80M 2>/dev/null | sed 's/^/  SKIPPED (>80MB, grep it manually): /' | tee -a "$REPORT" >/dev/null
  find "$HOME/.claude/projects" -name '*.jsonl' -mtime -60 -size -80M 2>/dev/null | while IFS= read -r t; do
    n=$(grep -cE "$PAT" "$t" 2>/dev/null || true); [ "${n:-0}" -gt 0 ] && log "  $n occurrence(s) in $t" && grep -oE ".{0,80}($PAT).{0,120}" "$t" | head -5 | sed 's/^/      /' | tee -a "$REPORT" >/dev/null
  done
  log "  (end — if nothing appeared above, no recent transcript contains these patterns)"
fi
[ -f "$HOME/.claude/fence-alarms.log" ] && { log "-- Tripwire alarms (fence-alarms.log, last 20) --"; tail -20 "$HOME/.claude/fence-alarms.log" | sed 's/^/  /' | tee -a "$REPORT" >/dev/null; }

# ------------------------------------------------------------- F. SUMMARY
hdr "F. NEXT STEPS"
log "  1. Read section B: each hit is [category] file:line. Open the file and judge the context."
log "  2. Read section C: any hook/MCP/plugin/allow you did not install = suspect."
log "  3. Read section D: unknown cron, rc lines, git hooksPath, remotes or authorized_keys = compromise beyond the AI."
log "  4. Run Phase 2 of the protocol (Claude-assisted review) with THIS report as input."
log "  5. Do NOT delete anything yet — move it to quarantine (it is evidence). Then rotate secrets."
log ""
log "Report saved to: $REPORT"
