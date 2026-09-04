#!/usr/bin/env python3
"""
guard-irreversible.py — Tripwire · Camada A (PreToolUse) · edição cliente Gauzzi & Co v1.0

Força um pedido de aprovação explícita ("ask") ANTES de qualquer ação que:
  (1) envie dados para fora — e-mail, compartilhamento de arquivo, HTTP POST/upload,
      transferência para servidor/nuvem, webhook, git push para remote desconhecido,
      ferramentas MCP de envio/compartilhamento/publicação;
  (2) seja irreversível — deletar, force-push, formatar, apagar recursos de nuvem;
  (3) modifique as próprias defesas do Claude ou a persistência da máquina —
      hooks, settings, agents, skills, memórias, CLAUDE.md, shell rc, git config, ssh, cron.
E NEGA ("deny") sem perguntar o que nunca é legítimo em uma sessão normal: desligar as
permissões, mandar dados para serviços de webhook/colagem, codificar-e-enviar, netcat.

Leituras e edições comuns passam sem atrito. A decisão padrão é "ask" para você continuar
no controle; troque por deny() nos pontos que quiser tornar inegociáveis.

FALHA FECHADA: qualquer erro do hook vira um pedido de aprovação nomeando a falha —
um portão de segurança nunca falha em silêncio.

Instalação: ~/.claude/hooks/guard-irreversible.py + bloco "hooks" no settings.json.
Ajuste o bloco CONFIG abaixo antes de usar.
"""

import json
import os
import re
import shlex
import subprocess
import sys

# ------------------------------------------------------------------ CONFIG
OWNER_EMAILS = {"voce@suaempresa.com.br"}  # e-mail só para si mesmo passa sem perguntar
ALLOWED_GIT_REMOTES = re.compile(r"github\.com[:/](SUA-ORG|seu-usuario)/", re.I)  # push liberado; o resto pergunta
GATE_SECRET_READS = True  # perguntar quando um comando lê .env/chaves/keychain
PROTECTED_PATHS = re.compile(
    r"/\.claude/(hooks|agents|commands|skills|plugins|memory|rules)/|/\.claude/projects/[^/]+/memory/|/\.claude/settings[^/]*\.json$|"
    r"/CLAUDE(\.local)?\.md$|/MEMORY\.md$|/\.claude\.json$|/\.mcp\.json$|/claude_desktop_config\.json$|"
    r"/\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile|gitconfig|npmrc|netrc)$|/\.ssh/|/\.aws/|"
    r"/Library/LaunchAgents/|/\.config/systemd/|/\.cursor/rules/|/\.cursorrules$|/AGENTS\.md$|/copilot-instructions\.md$",
    re.I,
)
# ---------------------------------------------------------------------------


def _out(decision, reason):
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def ask(reason):
    _out("ask", reason)


def deny(reason):
    _out("deny", "BLOQUEADO pelo Tripwire: " + reason)


def allow():
    sys.exit(0)


def git_remote_url(cwd, remote):
    try:
        return subprocess.run(
            ["git", "-C", cwd, "remote", "get-url", remote],
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout.strip()
    except Exception:
        return ""


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        ask(
            "guard-irreversible não conseguiu ler a entrada — FALHANDO FECHADO. Aprove conscientemente ou conserte/desative o hook no settings.json."
        )

    tool = data.get("tool_name", "") or ""
    tin = data.get("tool_input", {}) or {}
    cwd = data.get("cwd") or os.getcwd()

    # ---- 0) Escrita em arquivos protegidos (defesas, instruções, persistência)
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = (tin.get("file_path") or tin.get("notebook_path") or "").replace("\\", "/")
        if PROTECTED_PATHS.search(path):
            ask(
                "Isto modifica um arquivo PROTEGIDO (instruções/defesas/persistência da máquina): "
                + path
                + ". Uma injeção persiste exatamente assim. Aprove só se VOCÊ pediu esta edição."
            )
        allow()

    # ---- 1) Ferramentas não-Bash (MCP etc.): decide pelo nome
    if tool != "Bash":
        n = tool.lower()
        if re.search(r"(delete|trash|destroy|purge|remove|revoke)", n):
            ask(f"A ferramenta '{tool}' apaga/revoga algo (irreversível). Aprove para prosseguir.")
        if re.search(
            r"(send|share|publish|forward|invite|upload|post_message|create_comment|permission|reply|move_to)",
            n,
        ):
            ask(
                f"A ferramenta '{tool}' pode ENVIAR dados para fora ou torná-los visíveis a terceiros. Confira destinatários/conteúdo e aprove."
            )
        allow()

    # ---- 2) Bash
    cmd = tin.get("command", "") or ""
    low = cmd.lower()

    # 2a) NEGAR sem perguntar — nunca é legítimo numa sessão normal
    for p, why in (
        (
            r"--dangerously-skip-permissions|bypasspermissions|\"defaultmode\"\s*:\s*\"bypass",
            "tenta DESLIGAR as permissões do Claude Code",
        ),
        (
            r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok\.(io|app|dev)|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|requestbin|pipedream\.net|hookbin|burpcollaborator|interact\.sh|oastify\.com",
            "envia dados para um serviço de webhook/colagem — canal clássico de exfiltração",
        ),
        (
            r"\bbase64\b[^|]*\|\s*(curl|wget|nc|ncat)\b|\b(curl|wget)\b.*\$\(\s*base64",
            "codifica-e-envia dados — padrão de exfiltração",
        ),
        (
            r"/dev/(tcp|udp)/|(^|[\s;&|])(nc|ncat|socat)\s",
            "abre conexão de rede crua (netcat/socat)",
        ),
        (
            r"(^|[\s;&|])(rm|shred)\s+(-\w*\s+)*(\"?~|\$home|/users/|/home/)[^\s]*\.claude/(hooks|settings)",
            "apaga as próprias defesas do Claude",
        ),
    ):
        if re.search(p, low):
            deny(why + ". Se for realmente intencional, rode você mesmo no terminal.")

    # 2b) E-mail
    if re.search(
        r"\bgws\b.*\bgmail\b.*(\+send|\+reply|\+reply-all|\+forward|\b(messages|drafts)\b.*\bsend\b)|\bsendmail\b|\bmail\s+-s\b|\bmutt\b.*\s-s\b|\bhimalaya\b.*\bsend\b|osascript.*(mail|send)",
        low,
    ):
        flag_vals = re.findall(r"--(?:to|cc|bcc)[=\s]+([^\s]+)", low)
        rcpts = set()
        for v in flag_vals:
            rcpts |= set(re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", v))
        if rcpts and rcpts <= {e.lower() for e in OWNER_EMAILS}:
            allow()
        ext = [r for r in rcpts if r.split("@")[1] not in {e.split("@")[1].lower() for e in OWNER_EMAILS}]
        ask(
            "Este comando ENVIA e-mail (irreversível)"
            + (f" para domínio EXTERNO: {', '.join(sorted(ext))}" if ext else "")
            + ". Confira destinatários e anexos, e aprove."
        )

    # 2c) Compartilhamento / publicação
    for p, why in (
        (
            r"\bgws\b.*\bdrive\b.*\bpermissions?\b.*\b(create|update|insert)\b|\bgws\b.*\bshare\b",
            "altera permissões de compartilhamento de um arquivo no Drive",
        ),
        (
            r"\bgws\b.*\bcalendar\b.*\b(insert|patch|update|import|quickadd)\b.*(sendupdates|attendees)",
            "cria/edita evento visível a outros participantes",
        ),
        (
            r"\bgh\b\s+(gist\s+create|repo\s+create.*--public|release\s+(create|upload)|secret\s+set)",
            "publica conteúdo no GitHub / altera segredos",
        ),
        (
            r"\bgh\b\s+(issue|pr)\s+(comment|create)|\bglab\b.*(comment|create)",
            "posta texto em um issue/PR (visível a terceiros)",
        ),
    ):
        if re.search(p, low):
            ask(f"Este comando {why}. Aprove só se foi você quem pediu.")

    # 2d) HTTP POST / upload / transferência
    for p, why in (
        (
            r"\bcurl\b.*(\s-d\s|--data|--form|\s-F\s|\s-T\s|--upload-file|--json|-x\s*(post|put|patch))",
            "faz POST/upload de dados pela internet",
        ),
        (
            r"\bwget\b.*(--post-data|--post-file|--body-)",
            "faz POST de dados pela internet",
        ),
        (r"(^|[\s;&|])https?\s+(post|put|patch)\b", "faz POST via httpie"),
        (
            r"requests\.(post|put|patch)\(|urllib\.request|axios\.(post|put)\(|fetch\([^)]*method\s*:\s*['\"]?(post|put)|invoke-(webrequest|restmethod).*-method\s+(post|put)",
            "faz POST via script inline",
        ),
        (
            r"(^|[\s;&|])(scp|sftp)\s|\brsync\b.*\S+@\S+:|\brclone\s+(copy|sync|move)|\baws\s+s3\s+(cp|sync|mv)|\bgsutil\s+(cp|rsync)|\bgcloud\s+storage\s+cp|\baz\s+storage\s+blob\s+upload|\bb2\s+upload",
            "transfere arquivos para outro host/nuvem",
        ),
        (
            r"\bcurl\b.*https?://\d{1,3}(\.\d{1,3}){3}",
            "fala com um endereço IP cru (sem domínio)",
        ),
    ):
        if re.search(p, low):
            ask(f"Este comando {why}. Dados/IP podem sair da máquina — confira destino e conteúdo, e aprove.")

    # 2e) git push / remotes
    if re.search(r"\bgit\b.*\bpush\b", low):
        if re.search(r"--force\b|--force-with-lease\b|\s-f\b", low):
            ask("Este comando faz FORCE-PUSH (reescreve histórico). Aprove para prosseguir.")
        try:
            toks = shlex.split(cmd)
        except Exception:
            toks = cmd.split()
        remote = "origin"
        if "push" in toks:
            after = [t for t in toks[toks.index("push") + 1 :] if not t.startswith("-")]
            if after:
                remote = after[0]
        url = remote if "://" in remote or "@" in remote else git_remote_url(cwd, remote)
        if url and ALLOWED_GIT_REMOTES.search(url):
            allow()
        ask(
            f"git push para remote '{remote}' ({url or 'url desconhecida'}) — fora da lista permitida. Push para um remote estranho = exfiltração do repositório. Aprove só se reconhece o destino."
        )
    if re.search(r"\bgit\b\s+remote\s+(add|set-url)\b", low):
        ask("Este comando adiciona/altera um remote git — verifique a URL antes de aprovar.")

    # 2f) Leitura de segredos (opcional)
    if GATE_SECRET_READS and re.search(
        r"(cat|less|head|tail|grep|open|cp|base64)\b.*(\.env\b|\.pem\b|\.p12\b|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc)|security\s+find-(generic|internet)-password|(^|[\s;&|])(env|printenv)\s*($|\||>)",
        low,
    ):
        ask(
            "Este comando LÊ segredos/credenciais. Se o próximo passo for enviar algo, isso é vazamento. Aprove só se faz sentido no que você pediu."
        )

    # 2g) Persistência da máquina / autodefesa via shell
    for p, why in (
        (
            r">>?\s*\S*(/\.claude/(hooks|settings|agents|commands|skills|memory)|/claude\.md|/\.(zshrc|bashrc|bash_profile|profile|gitconfig)|/\.ssh/)",
            "escreve em arquivo protegido via redirecionamento",
        ),
        (
            r"\bcrontab\b\s+(-e|-|\S+\.txt)|\blaunchctl\s+(load|bootstrap)|\bsystemctl\s+--user\s+(enable|start)",
            "instala uma tarefa agendada (persistência)",
        ),
        (
            r"\bgit\s+config\b.*(core\.hookspath|init\.templatedir|include\.path)",
            "muda onde o git executa hooks (execução silenciosa)",
        ),
        (
            r"\bchmod\b.*\+x\b.*(/\.claude/|/\.config/)|\bcp\b.*\s\S*/\.claude/hooks/",
            "instala executável nas pastas de configuração",
        ),
        (
            r"\bnpm\s+(i|install)\b.*-g\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bnpx\s+skills\b|\bclaude\s+(mcp\s+add|plugin\s+install)",
            "instala software/plugin/MCP novo",
        ),
    ):
        if re.search(p, low):
            ask(f"Este comando {why}. Aprove só se foi você quem pediu.")

    # 2h) Destrutivo (não-rm)
    for p, why in (
        (
            r"\bgws\b.*\b(messages|threads)\b.*\b(delete|trash)\b|\bgws\b.*\bdelete\b",
            "apaga e-mails/recursos do Google",
        ),
        (
            r"\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-\w*f",
            "descarta alterações no git",
        ),
        (r"\b(gcloud|aws|az)\b.*\b(delete|rm|remove)\b", "apaga recurso de nuvem"),
        (
            r"\bmkfs\b|\bdd\b.*\sof=|>\s*/dev/(disk|sd|rdisk)|\bdiskutil\s+erase",
            "escrita/formatação de disco",
        ),
        (
            r"\bstripe\b.*\b(delete|finalize|pay|send)\b",
            "executa ação financeira irreversível no Stripe",
        ),
    ):
        if re.search(p, low):
            ask(f"Este comando {why} (irreversível). Aprove para prosseguir.")

    # 2i) rm / delete — pergunta, exceto limpeza puramente temporária
    if re.search(r"(^|[\s;&|/])(rm|rmdir|shred|trash)(\s|$)", cmd) or re.search(r"\bfind\b.*\s-delete\b", cmd):
        EPHEMERAL = (
            "/tmp/",
            "/private/tmp/",
            "/var/folders/",
            "/private/var/folders/",
            "scratchpad",
            "/dev/null",
        )
        try:
            tokens = shlex.split(cmd)
        except Exception:
            tokens = []
        skip = {
            "rm",
            "rmdir",
            "shred",
            "trash",
            "find",
            "-delete",
            "&&",
            "||",
            ";",
            "|",
            "sudo",
        }
        paths = [t for t in tokens if not t.startswith("-") and t not in skip]
        if paths and all(any(e in p for e in EPHEMERAL) for p in paths):
            allow()
        ask("Este comando APAGA arquivos (irreversível). Aprove para prosseguir.")

    allow()


try:
    main()
except SystemExit:
    raise
except Exception as e:
    ask(
        f"guard-irreversible QUEBROU ({type(e).__name__}: {e}) — FALHANDO FECHADO. Aprove conscientemente ou conserte/desative o hook no settings.json."
    )
