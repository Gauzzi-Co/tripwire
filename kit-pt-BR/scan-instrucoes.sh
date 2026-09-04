#!/usr/bin/env bash
# scan-instrucoes.sh — Varredura de instruções e memórias envenenadas
# Protocolo Tripwire · Gauzzi & Co · edição cliente v1.0
#
# O QUE FAZ: inventaria TODOS os arquivos que dão instruções persistentes ao seu
# assistente de IA (CLAUDE.md, memórias, agents, skills, hooks, settings, MCP),
# procura assinaturas conhecidas de prompt injection, audita a configuração de
# permissões/hooks/MCP, verifica persistência fora do Claude (cron, shell rc,
# git hooks, ssh) e vasculha transcrições de sessão por comandos de exfiltração.
#
# O QUE NÃO FAZ: não usa LLM, não modifica nada, não envia nada. Só lê e gera
# um relatório em ~/security-scan/. Determinístico — um atacante não consegue
# "convencer" este script de nada.
#
# USO:  bash scan-instrucoes.sh                # varre $HOME (profundidade 8)
#       bash scan-instrucoes.sh /outra/pasta   # pastas extras
#       SCAN_MAXDEPTH=12 bash scan-instrucoes.sh
# Windows: rode no Git Bash ou WSL (o home é %USERPROFILE%).
# Nuvem sincronizada (Drive/OneDrive/iCloud): a leitura pode baixar arquivos
# "somente na nuvem" — aceite, ou exclua o caminho via EXCLUDE_EXTRA='pattern'.
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
log "Relatório: $REPORT"
log "Inventário: $LIST"

# ---------------------------------------------------------------- A. INVENTÁRIO
hdr "A. INVENTÁRIO — arquivos que instruem a IA (ordenados por modificação recente)"
PRUNE=( -path '*/node_modules' -o -path '*/.Trash' -o -path '*/Library/Caches' -o -path '*/Library/Containers' \
        -o -path '*/.npm' -o -path '*/.cache' -o -path '*/.cargo' -o -path '*/.rustup' -o -path '*/site-packages' \
        -o -path '*/.venv' -o -path '*/venv' -o -path '*/.git/objects' -o -path '*/Library/Application Support/Google' )

{
  # 1) arquivos de instrução de qualquer ferramenta de IA, em qualquer lugar do home
  find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type f \( \
       -name 'CLAUDE.md' -o -name 'CLAUDE.local.md' -o -name 'MEMORY.md' -o -name 'HANDOFF.md' \
       -o -name 'AGENTS.md' -o -name 'GEMINI.md' -o -name '.cursorrules' -o -name '.windsurfrules' \
       -o -name 'copilot-instructions.md' -o -name 'SKILL.md' -o -name '.mcp.json' \
       -o -name 'claude_desktop_config.json' -o \( -name '*.mdc' -path '*/.cursor/rules/*' \) \
       -o \( -name '*.md' -path '*/.claude/rules/*' \) \) -print 2>/dev/null
  # 2) tudo dentro dos diretórios .claude (global e de projetos): agents, commands, skills, hooks, memory, settings
  find "$HOME/.claude" -maxdepth 6 -type f \( -name '*.md' -o -name '*.json' -o -name '*.py' -o -name '*.sh' -o -name '*.js' -o -name '*.ts' \) \
       -not -path '*/projects/*/*.jsonl' -not -path '*/cache/*' -not -path '*/shell-snapshots/*' -not -path '*/file-history/*' \
       -not -path '*/paste-cache/*' -not -path '*/telemetry/*' -not -path '*/uploads/*' -not -path '*/sessions/*' -not -path '*/tool-results/*' -not -path '*/workflows/*' -not -path '*/subagents/*' -print 2>/dev/null
  find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type d -name '.claude' -not -path "$HOME/.claude" -print 2>/dev/null \
    | while IFS= read -r d; do find "$d" -maxdepth 4 -type f \( -name '*.md' -o -name '*.json' -o -name '*.py' -o -name '*.sh' -o -name '*.js' \) -print 2>/dev/null; done
  # 3) configs de nível de usuário
  for f in "$HOME/.claude.json" "$HOME/.codex/config.toml" "$HOME/.codex/instructions.md" "$HOME/.gemini/settings.json" \
           "$HOME/Library/Application Support/Claude/claude_desktop_config.json" "$APPDATA/Claude/claude_desktop_config.json"; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
} 2>/dev/null | grep -v -E "$EXCLUDE_EXTRA" | sort -u > "$LIST"

TOTAL=$(wc -l < "$LIST" | tr -d ' ')
log "Arquivos encontrados: $TOTAL"
log ""
log "  MODIFICADO           TAMANHO  SHA256(12)     CAMINHO"
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f" >/dev/null 2>&1; then mt=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$f"); sz=$(stat -f '%z' "$f");
  else mt=$(stat -c '%y' "$f" | cut -c1-16); sz=$(stat -c '%s' "$f"); fi
  sha=$(shasum -a 256 "$f" 2>/dev/null | cut -c1-12)
  printf '  %s  %7s  %s   %s\n' "$mt" "$sz" "$sha" "$f"
done < "$LIST" | sort -r | tee -a "$REPORT" >/dev/null
log ""
log "  ^ Modificações que VOCÊ não reconhece nas últimas semanas são o primeiro sinal."

# ---------------------------------------------------- B. ASSINATURAS + OCULTAÇÃO
hdr "B. ASSINATURAS DE PROMPT INJECTION + CONTEÚDO OCULTO (por arquivo:linha)"
python3 - "$LIST" <<'PYEOF' | tee -a "$REPORT"
import sys, re, os
files = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8", errors="replace") if l.strip()]
SIGS = [
 ("SIGILO / ocultar do usuário",
  re.compile(r"(never|do not|don'?t|nunca|n[ãa]o)\s+(tell|alert|inform|notify|mention|reveal|disclose|show|display|conte|avise|informe|mencione|revele|mostre)\b.{0,50}\b(user|owner|human|operator|usu[áa]rio|dono|ele|ela|voc[êe])|"
             r"(conceal|hide|keep\s+(this|it)\s+(secret|hidden|private)|secretly|silently|without\s+(telling|informing|asking|notifying)|"
             r"oculte|esconda|em\s+segredo|sem\s+(avisar|informar|perguntar)|n[ãa]o\s+(mencione|revele|mostre)\s+(isso|isto|esta|este))", re.I)),
 ("OVERRIDE / reenquadramento",
  re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)|disregard\s+(all\s+)?(previous|prior)|you\s+are\s+now|new\s+instructions|"
             r"system\s+prompt|developer\s+message|from\s+now\s+on\s+(always|never)|desconsidere\s+(as\s+)?(instru[çc][õo]es|regras)|"
             r"ignore\s+(as\s+)?instru[çc][õo]es\s+anteriores|voc[êe]\s+agora\s+[ée]|novas\s+instru[çc][õo]es", re.I)),
 ("AUTO-APROVAÇÃO / sem permissão",
  re.compile(r"(always|automatically|sempre|automaticamente)\s+(approve|allow|accept|run|execute|aprove|permita|aceite|execute)|"
             r"without\s+(confirmation|permission|approval)|do\s+not\s+ask\s+(for\s+)?(permission|confirmation)|"
             r"n[ãa]o\s+pe[çc]a\s+(permiss[ãa]o|confirma[çc][ãa]o)|dangerously-skip-permissions|bypasspermissions", re.I)),
 ("EXFILTRAÇÃO / envio para fora",
  re.compile(r"(send|post|upload|forward|transmit|exfil|sync|mirror|envie|poste|suba|encaminhe|transmita|sincronize)\b.{0,60}\b(to|para)\b.{0,60}(https?://|@|webhook|endpoint|server|bucket|api)|"
             r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok\.(io|app|dev)|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|requestbin|pipedream\.net|burpcollaborator|oastify\.com|interact\.sh", re.I)),
 ("COLETA DE SEGREDOS",
  re.compile(r"(collect|gather|read|copy|include|extract|colete|leia|copie|inclua|extraia)\b.{0,50}\b(api[_ -]?keys?|tokens?|passwords?|secrets?|credentials?|\.env\b|id_rsa|id_ed25519|private\s+key|senhas?|credenciais|chaves?\s+(de\s+)?api)", re.I)),
 ("PERSISTÊNCIA / gravar em memória",
  re.compile(r"(remember|save|store|add|write|persist|memorize|lembre|salve|guarde|adicione|grave)\b.{0,40}\b(to|in|into|em|no|na)\b.{0,30}(memory|mem[óo]ria|CLAUDE\.md|MEMORY\.md|settings|hooks?)", re.I)),
 ("SABOTAGEM de guardrails",
  re.compile(r"(disable|remove|delete|comment\s+out|bypass|skip|desative|remova|apague|comente|contorne|pule)\b.{0,40}\b(hooks?|guards?|guardrails?|safety|checks?|tests?|lint|verifica[çc][õo]es|seguran[çc]a)", re.I)),
 ("IMPERATIVO dirigido à IA",
  re.compile(r"\b(assistant|claude|ai|agent|copilot|assistente|agente)\b[^.\n]{0,40}\b(must|should|will|deve|precisa)\s+(run|execute|send|forward|delete|download|install|approve|executar|enviar|encaminhar|apagar|baixar|instalar|aprovar)\b", re.I)),
]
ZW = re.compile("[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]")
B64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
HTMLC = re.compile(r"<!--.*?-->", re.S)
hits = 0; hidden = 0
for f in files:
    try:
        if os.path.getsize(f) > 5_000_000: print(f"  [pulado >5MB] {f}"); continue
        text = open(f, encoding="utf-8", errors="replace").read()
    except Exception as e:
        print(f"  [erro lendo] {f}: {e}"); continue
    for i, line in enumerate(text.splitlines(), 1):
        for label, rx in SIGS:
            m = rx.search(line)
            if m:
                hits += 1
                snip = line.strip()[:220]
                print(f"  [{label}] {f}:{i}\n      {snip}")
    zw = ZW.findall(text)
    if zw:
        hidden += 1; print(f"  [OCULTO: {len(zw)} caractere(s) invisível/bidi] {f}  <- texto invisível para humanos, legível pela IA")
    for m in HTMLC.finditer(text):
        body = m.group(0)
        if len(body) > 60 and f.lower().endswith((".md", ".mdc", ".txt")):
            hidden += 1; print(f"  [OCULTO: comentário HTML em markdown, {len(body)} chars] {f}\n      {body[:200].replace(chr(10),' ')}")
    if B64.search(text) and not f.endswith((".json", ".jsonl", ".png", ".svg")):
        hidden += 1; print(f"  [OCULTO: bloco base64 longo] {f}")
    longl = [i for i, l in enumerate(text.splitlines(), 1) if (re.search(r"[ \t]{60,}\S", l) or len(l) > 3000) and f.lower().endswith((".md", ".mdc", ".txt"))]
    if longl:
        hidden += 1; print(f"  [OCULTO: linha(s) com preenchimento de espaços ou >3000 chars — pode esconder instruções fora da tela] {f}: linhas {longl[:5]}")
print(f"\n  TOTAL: {hits} assinatura(s) textual(is), {hidden} indicador(es) de conteúdo oculto.")
print("  Falsos positivos são esperados (ex.: um hook de segurança CITA as próprias assinaturas). Revise cada um na Fase 2.")
PYEOF

# ----------------------------------------------------------- C. CONFIG / HOOKS / MCP
hdr "C. AUDITORIA DE CONFIGURAÇÃO — permissões, hooks, servidores MCP, plugins"
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
    print(f"    defaultMode: {perm.get('defaultMode', '(padrão)')}")
    for k in ("allow", "deny", "ask"):
        v = perm.get(k) or []
        if v: print(f"    permissions.{k} ({len(v)}): " + "; ".join(map(str, v))[:900])
    broad = [r for r in (perm.get("allow") or []) if re.search(r"Bash\(\*?\)|Bash\(\*\)|^Bash$|curl|wget|scp|rclone|\brm\b", str(r))]
    if broad: print(f"    !! ALLOW AMPLO (revise): {broad}")
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
                        print(f"      -> {path}  sha256:{sha(path)}\n         início: {head[:300]}")
                    else:
                        print(f"      -> !! ARQUIVO DO HOOK NÃO EXISTE: {path}")
                if re.search(r"curl|wget|nc |base64|python -c|eval|\$\(", cmd) and not re.search(r"\.(py|sh|js)\b", cmd):
                    print("      !! HOOK INLINE com rede/eval — todo hook roda em TODA chamada de ferramenta: leia com atenção")
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
    print(f"\n  PLUGINS em {plug}:")
    for root in sorted(glob.glob(os.path.join(plug, "*"))): print(f"    {root}")
print("\n  Revise: cada MCP/plugin/hook que você NÃO instalou conscientemente é suspeito. Hooks rodam código a cada ferramenta.")
PYEOF

# ------------------------------------------------- D. PERSISTÊNCIA FORA DO CLAUDE
hdr "D. PERSISTÊNCIA FORA DO CLAUDE — cron, launch agents, shell rc, git, ssh, binário"
log "-- Binário 'claude' (aliases/wrappers na frente do binário real são um vetor) --"
type claude 2>&1 | head -3 | tee -a "$REPORT" >/dev/null
command -v -a claude 2>/dev/null | tee -a "$REPORT" >/dev/null
log "-- crontab --"; (crontab -l 2>/dev/null || echo "  (vazio)") | tee -a "$REPORT" >/dev/null
if [ -d "$HOME/Library/LaunchAgents" ]; then
  log "-- LaunchAgents (macOS) --"
  for f in "$HOME"/Library/LaunchAgents/*.plist; do [ -f "$f" ] && log "  $f" && grep -A3 -i "ProgramArguments" "$f" 2>/dev/null | grep -o "<string>.*</string>" | head -4 | sed 's/^/      /' | tee -a "$REPORT" >/dev/null; done
fi
[ -d "$HOME/.config/systemd/user" ] && { log "-- systemd user units --"; ls -la "$HOME/.config/systemd/user" | tee -a "$REPORT" >/dev/null; }
log "-- Shell rc (linhas suspeitas: rede, base64, eval, alias claude) --"
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [ -f "$f" ] || continue
  mt=$(stat -f '%Sm' -t '%Y-%m-%d' "$f" 2>/dev/null || stat -c '%y' "$f" | cut -c1-10)
  log "  $f (modificado $mt)"
  grep -nE 'curl|wget|base64|eval |nc |/dev/tcp|python[3]? -c|alias claude=|claude\(\)|PROMPT_COMMAND|precmd' "$f" 2>/dev/null | sed 's/^/      /' | tee -a "$REPORT" >/dev/null
done
log "-- Git global (hooksPath/templateDir/includes são vetores de execução silenciosa) --"
git config --global --list 2>/dev/null | grep -iE 'hookspath|templatedir|include|credential|url\.' | sed 's/^/  /' | tee -a "$REPORT" >/dev/null || log "  (nada)"
log "-- SSH --"
[ -f "$HOME/.ssh/authorized_keys" ] && log "  authorized_keys: $(wc -l < "$HOME/.ssh/authorized_keys" | tr -d ' ') chave(s), modificado $(stat -f '%Sm' -t '%Y-%m-%d' "$HOME/.ssh/authorized_keys" 2>/dev/null || stat -c '%y' "$HOME/.ssh/authorized_keys" | cut -c1-10)"
[ -f "$HOME/.ssh/config" ] && grep -nE 'ProxyCommand|LocalCommand|PermitLocalCommand' "$HOME/.ssh/config" 2>/dev/null | sed 's/^/  ssh config: /' | tee -a "$REPORT" >/dev/null
log "-- Remotes git de todos os repositórios (remotes que você não reconhece = exfiltração por push) --"
find "$HOME" "$@" -maxdepth "$MAXDEPTH" \( "${PRUNE[@]}" \) -prune -o -type d -name '.git' -print 2>/dev/null | while IFS= read -r g; do
  r="$(dirname "$g")"; git -C "$r" remote -v 2>/dev/null | awk -v repo="$r" '/\(push\)/{print "  " $2 "   <- " repo}'
done | sort -u | tee -a "$REPORT" >/dev/null

# ------------------------------------------------- E. FORENSE DE SESSÕES
hdr "E. FORENSE DE SESSÕES — comandos de exfiltração executados nos últimos 60 dias"
PAT='curl [^"]*(-d |--data|-F |-T |--upload-file|-X POST|-X PUT|--json)|wget [^"]*--post|gws gmail \+(send|reply|forward)|\bscp |\brsync [^"]*@|\brclone (copy|sync|move)|aws s3 (cp|sync)|gsutil (cp|rsync)|webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|dangerously-skip-permissions|base64 [^"]*\| *curl|/dev/tcp/'
log "  (esta seção varre todas as transcrições dos últimos 60 dias; em máquina pesada pode levar vários minutos — transcrições acima de 80 MB são puladas e listadas)"
if [ -d "$HOME/.claude/projects" ]; then
  find "$HOME/.claude/projects" -name '*.jsonl' -mtime -60 -size +80M 2>/dev/null | sed 's/^/  PULADA (>80MB, grep manual): /' | tee -a "$REPORT" >/dev/null
  find "$HOME/.claude/projects" -name '*.jsonl' -mtime -60 -size -80M 2>/dev/null | while IFS= read -r t; do
    n=$(grep -cE "$PAT" "$t" 2>/dev/null || true); [ "${n:-0}" -gt 0 ] && log "  $n ocorrência(s) em $t" && grep -oE ".{0,80}($PAT).{0,120}" "$t" | head -5 | sed 's/^/      /' | tee -a "$REPORT" >/dev/null
  done
  log "  (fim — se nada apareceu acima, nenhuma transcrição recente contém esses padrões)"
fi
[ -f "$HOME/.claude/fence-alarms.log" ] && { log "-- Alarmes do Tripwire (fence-alarms.log, últimos 20) --"; tail -20 "$HOME/.claude/fence-alarms.log" | sed 's/^/  /' | tee -a "$REPORT" >/dev/null; }

# ------------------------------------------------------------- F. RESUMO
hdr "F. PRÓXIMOS PASSOS"
log "  1. Leia a seção B: cada hit é [categoria] arquivo:linha. Abra o arquivo e julgue o contexto."
log "  2. Leia a seção C: qualquer hook/MCP/plugin/allow que você não instalou = suspeito."
log "  3. Leia a seção D: cron, rc, git hooksPath, remotes e authorized_keys desconhecidos = comprometimento além da IA."
log "  4. Rode a Fase 2 do protocolo (revisão assistida com o Claude) usando ESTE relatório como entrada."
log "  5. NÃO apague nada ainda — mova para quarentena (é evidência). Depois rotacione segredos."
log ""
log "Relatório salvo em: $REPORT"
