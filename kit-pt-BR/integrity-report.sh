#!/usr/bin/env bash
# integrity-report.sh — Tripwire · relatório semanal de integridade · edição cliente v1.0
# Verifica que as defesas existem, estão registradas e falham fechado; mostra o que mudou
# nas memórias/instruções desde a última baseline (git em ~/.claude) e procura assinaturas
# de injeção SÓ no conteúdo novo. Exit 1 se houver problema CRÍTICO.
# Pré-requisito: ~/.claude versionado com git (ver documento, seção Tripwire › passo 3).
set -uo pipefail
CLAUDE_DIR="$HOME/.claude"; FAIL=0
echo "== RELATÓRIO DE INTEGRIDADE TRIPWIRE — $(date '+%Y-%m-%d %H:%M %Z') =="

echo; echo "-- Binário claude (alias/função na frente do binário = vetor) --"
type claude 2>&1 | head -2

echo; echo "-- Changelog das defesas (git, últimas 10 mudanças) --"
if git -C "$CLAUDE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$CLAUDE_DIR" log --oneline -10
  echo; echo "-- Mudanças NÃO commitadas na superfície de defesa --"
  CH="$(git -C "$CLAUDE_DIR" status --porcelain -- settings.json hooks/ agents/ commands/ skills/ CLAUDE.md 2>/dev/null)"
  if [ -n "$CH" ]; then echo "$CH"; echo "^ defesas alteradas sem commit — se você não fez isso, INVESTIGUE antes de commitar."; else echo "limpo."; fi
else
  echo "CRÍTICO: ~/.claude não é um repositório git — sem baseline, sem detecção de adulteração."; FAIL=1
fi

echo; echo "-- Arquivos de hook presentes --"
for f in guard-irreversible.py guard-untrusted-data.py tripwire-run.sh; do
  if [ -f "$CLAUDE_DIR/hooks/$f" ]; then echo "  OK    $f"; else echo "  CRÍTICO: FALTANDO $f"; FAIL=1; fi
done
echo; echo "-- Hooks registrados no settings.json --"
for f in guard-irreversible.py guard-untrusted-data.py; do
  if grep -q "$f" "$CLAUDE_DIR/settings.json" 2>/dev/null; then echo "  OK    $f"; else echo "  CRÍTICO: NÃO REGISTRADO $f"; FAIL=1; fi
done
echo; echo "-- Teste de falha-fechada (entrada inválida deve produzir resposta ALTA) --"
for f in guard-irreversible.py guard-untrusted-data.py; do
  out="$(echo 'not json {{{' | python3 "$CLAUDE_DIR/hooks/$f" 2>/dev/null || true)"
  if printf '%s' "$out" | grep -qE '"permissionDecision": *"(ask|deny)"|additionalContext'; then echo "  OK    $f (grita no erro)"; else echo "  CRÍTICO: $f SILENCIOSO ou permissivo no erro"; FAIL=1; fi
done

echo; echo "-- Permissões perigosas no settings --"
for SF in "$CLAUDE_DIR/settings.json" "$CLAUDE_DIR/settings.local.json"; do [ -f "$SF" ] || continue; echo "  ($SF)"
python3 - "$SF" <<'PYEOF'
import json, sys, re
try: d = json.load(open(sys.argv[1]))
except Exception as e: print("  (não consegui ler settings.json:", e, ")"); sys.exit(0)
p = d.get("permissions", {})
if p.get("defaultMode") in ("bypassPermissions",): print("  CRÍTICO: defaultMode = bypassPermissions")
bad = [r for r in p.get("allow", []) if re.search(r"^Bash$|Bash\(\*?\)|Bash\(\*\)|curl|wget|scp|rclone|\brm\b", str(r))]
print("  allow amplo:", bad if bad else "nenhum")
if d.get("disableAllHooks"): print("  CRITICAL: disableAllHooks is set — every hook is off")
hk = d.get("hooks", {}) or {}
pre = [e for e in hk.get("PreToolUse", []) if any("guard-irreversible" in (h.get("command") or "") for h in e.get("hooks", []))]
if pre and not any(re.search(r"Bash", e.get("matcher", "")) for e in pre): print("  CRITICAL: guard-irreversible is registered but its matcher does not cover Bash")
PYEOF
done

echo; echo "-- Drift de memórias/instruções desde a baseline --"
DRIFT="$(git -C "$CLAUDE_DIR" status --porcelain -uall -- projects/ CLAUDE.md 2>/dev/null || true)"
if [ -n "$DRIFT" ]; then
  echo "$DRIFT" | sed 's/^/  /'
  echo "$DRIFT" | grep -q '^.D' && echo "  NOTA: há deleções — confirme cada uma (envenenamento também pode ser apagamento)."
  echo "  ^ revise; se tudo for seu, commite como nova baseline."
else echo "  limpo — nenhuma mudança."; fi

echo; echo "-- Tripwire de envenenamento (assinaturas SÓ no conteúdo novo) --"
TMPF="$(mktemp)"
{ git -C "$CLAUDE_DIR" diff HEAD -- projects/ CLAUDE.md 2>/dev/null | grep '^+' | grep -v '^+++' || true
  git -C "$CLAUDE_DIR" ls-files --others --exclude-standard -- projects/ 2>/dev/null | while IFS= read -r f; do cat "$CLAUDE_DIR/$f" 2>/dev/null; done
} > "$TMPF"
if [ ! -s "$TMPF" ]; then echo "  sem conteúdo novo para escanear."; else
HITS="$(python3 - "$TMPF" <<'PYEOF'
import sys, re
t = open(sys.argv[1], encoding="utf-8", errors="replace").read()
sigs = [
 (re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)|desconsidere\s+(as\s+)?instru", re.I), "override"),
 (re.compile(r"you are now|new instructions|system prompt|developer message|novas instru", re.I), "reenquadramento"),
 (re.compile(r"(never|do not|don'?t|nunca|n[ãa]o)\s+(tell|alert|inform|notify|mention|reveal|conte|avise|informe|mencione|revele)\b.{0,40}\b(user|owner|usu[áa]rio|dono|him|her|them|ele|ela)", re.I), "sigilo"),
 (re.compile("[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\U000E0000-\U000E007F]"), "unicode invisível"),
 (re.compile(r"(send|post|upload|forward|envie|poste|encaminhe)\b.{0,60}\b(to|para)\b.{0,60}(https?://|@|webhook)", re.I), "exfiltração"),
 (re.compile(r"dangerously-skip-permissions|bypasspermissions|(always|sempre)\s+(approve|allow|aprove|permita)", re.I), "auto-aprovação"),
]
for rx, label in sigs:
    m = rx.search(t)
    if m: print(f"{label}: ...{t[max(0,m.start()-40):m.end()+40]!r}...")
PYEOF
)"
if [ -n "$HITS" ]; then echo "  CRÍTICO: assinatura(s) em conteúdo NOVO — NÃO commite baseline; rode o protocolo de varredura:"; echo "$HITS" | sed 's/^/    /'; FAIL=1
else echo "  OK    nenhuma assinatura no conteúdo novo."; fi; fi
rm -f "$TMPF"

[ -f "$CLAUDE_DIR/fence-alarms.log" ] && { echo; echo "-- Alarmes da cerca (últimos 10) --"; tail -10 "$CLAUDE_DIR/fence-alarms.log" | sed 's/^/  /'; }

echo; [ "$FAIL" -eq 0 ] && echo "VEREDITO: SAUDÁVEL" || echo "VEREDITO: PROBLEMAS CRÍTICOS — aja agora"
exit "$FAIL"
