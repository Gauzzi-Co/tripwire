#!/usr/bin/env python3
"""
guard-irreversible.py — Tripwire · Layer A (PreToolUse) · Gauzzi & Co client edition v1.0

Forces an explicit approval prompt ("ask") BEFORE any action that:
  (1) sends data out — email, file sharing, HTTP POST/upload, transfer to a server or
      cloud bucket, webhook, git push to an unknown remote, MCP tools that send/share/publish;
  (2) is irreversible — delete, force-push, format, destroy cloud resources;
  (3) modifies Claude's own defenses or the machine's persistence — hooks, settings,
      agents, skills, memories, CLAUDE.md, shell rc files, git config, ssh, cron.
And DENIES outright what is never legitimate in a normal session: disabling permissions,
sending data to webhook/paste services, encode-and-send, netcat.

Ordinary reads and edits flow without friction. The default decision is "ask" so you
stay in control; switch to deny() on the gates you want to make non-negotiable.

FAILS CLOSED: any error in the hook becomes an approval prompt naming the failure —
a safety gate must never fail silent.

Install: ~/.claude/hooks/guard-irreversible.py + the "hooks" block in settings.json.
Edit the CONFIG block below before use.
"""

import json
import os
import re
import shlex
import subprocess
import sys

# ------------------------------------------------------------------ CONFIG
OWNER_EMAILS = {"you@yourcompany.com"}  # mail sent only to yourself passes without asking
ALLOWED_GIT_REMOTES = re.compile(
    r"github\.com[:/](YOUR-ORG|your-username)/", re.I
)  # push allowed; everything else asks
GATE_SECRET_READS = True  # ask when a command reads .env / keys / keychain
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
    _out("deny", "BLOCKED by Tripwire: " + reason)


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
            "guard-irreversible could not parse its input — FAILING CLOSED. Approve consciously, or fix/disable the hook in settings.json."
        )

    tool = data.get("tool_name", "") or ""
    tin = data.get("tool_input", {}) or {}
    cwd = data.get("cwd") or os.getcwd()

    # ---- 0) Writes to protected files (defenses, instructions, machine persistence)
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = (tin.get("file_path") or tin.get("notebook_path") or "").replace("\\", "/")
        if PROTECTED_PATHS.search(path):
            ask(
                "This modifies a PROTECTED file (instructions / defenses / machine persistence): "
                + path
                + ". An injection persists exactly this way. Approve only if YOU asked for this edit."
            )
        allow()

    # ---- 1) Non-Bash tools (MCP etc.): decide by name
    if tool != "Bash":
        n = tool.lower()
        if re.search(r"(delete|trash|destroy|purge|remove|revoke)", n):
            ask(f"Tool '{tool}' deletes/revokes something (irreversible). Approve to proceed.")
        if re.search(
            r"(send|share|publish|forward|invite|upload|post_message|create_comment|permission|reply|move_to)",
            n,
        ):
            ask(
                f"Tool '{tool}' can SEND data out or make it visible to third parties. Check recipients/content and approve."
            )
        allow()

    # ---- 2) Bash
    cmd = tin.get("command", "") or ""
    low = cmd.lower()

    # 2a) DENY without asking — never legitimate in a normal session
    for p, why in (
        (
            r"--dangerously-skip-permissions|bypasspermissions|\"defaultmode\"\s*:\s*\"bypass",
            "tries to DISABLE Claude Code's permissions",
        ),
        (
            r"webhook\.site|hooks\.slack\.com|discord(app)?\.com/api/webhooks|ngrok\.(io|app|dev)|pastebin\.com|transfer\.sh|ntfy\.sh|api\.telegram\.org|requestbin|pipedream\.net|hookbin|burpcollaborator|interact\.sh|oastify\.com",
            "sends data to a webhook/paste service — a classic exfiltration channel",
        ),
        (
            r"\bbase64\b[^|]*\|\s*(curl|wget|nc|ncat)\b|\b(curl|wget)\b.*\$\(\s*base64",
            "encodes-and-sends data — an exfiltration pattern",
        ),
        (
            r"/dev/(tcp|udp)/|(^|[\s;&|])(nc|ncat|socat)\s",
            "opens a raw network connection (netcat/socat)",
        ),
        (
            r"(^|[\s;&|])(rm|shred)\s+(-\w*\s+)*(\"?~|\$home|/users/|/home/)[^\s]*\.claude/(hooks|settings)",
            "deletes Claude's own defenses",
        ),
    ):
        if re.search(p, low):
            deny(why + ". If this is truly intentional, run it yourself in a terminal.")

    # 2b) Email
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
            "This command SENDS email (irreversible)"
            + (f" to an EXTERNAL domain: {', '.join(sorted(ext))}" if ext else "")
            + ". Check recipients and attachments, then approve."
        )

    # 2c) Sharing / publishing
    for p, why in (
        (
            r"\bgws\b.*\bdrive\b.*\bpermissions?\b.*\b(create|update|insert)\b|\bgws\b.*\bshare\b",
            "changes sharing permissions on a Drive file",
        ),
        (
            r"\bgws\b.*\bcalendar\b.*\b(insert|patch|update|import|quickadd)\b.*(sendupdates|attendees)",
            "creates/edits an event visible to other attendees",
        ),
        (
            r"\bgh\b\s+(gist\s+create|repo\s+create.*--public|release\s+(create|upload)|secret\s+set)",
            "publishes content on GitHub / changes secrets",
        ),
        (
            r"\bgh\b\s+(issue|pr)\s+(comment|create)|\bglab\b.*(comment|create)",
            "posts text on an issue/PR (visible to third parties)",
        ),
    ):
        if re.search(p, low):
            ask(f"This command {why}. Approve only if you asked for it.")

    # 2d) HTTP POST / upload / transfer
    for p, why in (
        (
            r"\bcurl\b.*(\s-d\s|--data|--form|\s-F\s|\s-T\s|--upload-file|--json|-x\s*(post|put|patch))",
            "POSTs/uploads data over the internet",
        ),
        (
            r"\bwget\b.*(--post-data|--post-file|--body-)",
            "POSTs data over the internet",
        ),
        (r"(^|[\s;&|])https?\s+(post|put|patch)\b", "POSTs via httpie"),
        (
            r"requests\.(post|put|patch)\(|urllib\.request|axios\.(post|put)\(|fetch\([^)]*method\s*:\s*['\"]?(post|put)|invoke-(webrequest|restmethod).*-method\s+(post|put)",
            "POSTs via an inline script",
        ),
        (
            r"(^|[\s;&|])(scp|sftp)\s|\brsync\b.*\S+@\S+:|\brclone\s+(copy|sync|move)|\baws\s+s3\s+(cp|sync|mv)|\bgsutil\s+(cp|rsync)|\bgcloud\s+storage\s+cp|\baz\s+storage\s+blob\s+upload|\bb2\s+upload",
            "transfers files to another host/cloud",
        ),
        (
            r"\bcurl\b.*https?://\d{1,3}(\.\d{1,3}){3}",
            "talks to a raw IP address (no domain)",
        ),
    ):
        if re.search(p, low):
            ask(f"This command {why}. Data/IP may leave the machine — check destination and content, then approve.")

    # 2e) git push / remotes
    if re.search(r"\bgit\b.*\bpush\b", low):
        if re.search(r"--force\b|--force-with-lease\b|\s-f\b", low):
            ask("This command FORCE-PUSHES (rewrites history). Approve to proceed.")
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
            f"git push to remote '{remote}' ({url or 'unknown url'}) — not on the allowed list. Pushing to a strange remote = exfiltrating the repository. Approve only if you recognize the destination."
        )
    if re.search(r"\bgit\b\s+remote\s+(add|set-url)\b", low):
        ask("This command adds/changes a git remote — verify the URL before approving.")

    # 2f) Secret reads (optional)
    if GATE_SECRET_READS and re.search(
        r"(cat|less|head|tail|grep|open|cp|base64)\b.*(\.env\b|\.pem\b|\.p12\b|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc)|security\s+find-(generic|internet)-password|(^|[\s;&|])(env|printenv)\s*($|\||>)",
        low,
    ):
        ask(
            "This command READS secrets/credentials. If the next step is to send something, that is a leak. Approve only if it makes sense for what you asked."
        )

    # 2g) Machine persistence / self-modification via shell
    for p, why in (
        (
            r">>?\s*\S*(/\.claude/(hooks|settings|agents|commands|skills|memory)|/claude\.md|/\.(zshrc|bashrc|bash_profile|profile|gitconfig)|/\.ssh/)",
            "writes to a protected file via shell redirection",
        ),
        (
            r"\bcrontab\b\s+(-e|-|\S+\.txt)|\blaunchctl\s+(load|bootstrap)|\bsystemctl\s+--user\s+(enable|start)",
            "installs a scheduled task (persistence)",
        ),
        (
            r"\bgit\s+config\b.*(core\.hookspath|init\.templatedir|include\.path)",
            "changes where git executes hooks (silent execution)",
        ),
        (
            r"\bchmod\b.*\+x\b.*(/\.claude/|/\.config/)|\bcp\b.*\s\S*/\.claude/hooks/",
            "installs an executable into configuration folders",
        ),
        (
            r"\bnpm\s+(i|install)\b.*-g\b|\bpip3?\s+install\b|\bbrew\s+install\b|\bnpx\s+skills\b|\bclaude\s+(mcp\s+add|plugin\s+install)",
            "installs new software/plugin/MCP",
        ),
    ):
        if re.search(p, low):
            ask(f"This command {why}. Approve only if you asked for it.")

    # 2h) Destructive (non-rm)
    for p, why in (
        (
            r"\bgws\b.*\b(messages|threads)\b.*\b(delete|trash)\b|\bgws\b.*\bdelete\b",
            "deletes email/Google resources",
        ),
        (r"\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-\w*f", "discards git changes"),
        (r"\b(gcloud|aws|az)\b.*\b(delete|rm|remove)\b", "deletes a cloud resource"),
        (
            r"\bmkfs\b|\bdd\b.*\sof=|>\s*/dev/(disk|sd|rdisk)|\bdiskutil\s+erase",
            "writes to / formats a disk",
        ),
        (
            r"\bstripe\b.*\b(delete|finalize|pay|send)\b",
            "performs an irreversible financial action in Stripe",
        ),
    ):
        if re.search(p, low):
            ask(f"This command {why} (irreversible). Approve to proceed.")

    # 2i) rm / delete family — ask, unless confined to ephemeral temp dirs
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
        ask("This command DELETES files (irreversible). Approve to proceed.")

    allow()


try:
    main()
except SystemExit:
    raise
except Exception as e:
    ask(
        f"guard-irreversible CRASHED ({type(e).__name__}: {e}) — FAILING CLOSED. Approve consciously, or fix/disable the hook in settings.json."
    )
