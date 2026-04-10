"""
Fake Shell Engine
=================
Shared interactive fake shell logic used by Fake SSH and other interactive
honeypot services.

- Parses attacker commands
- Returns believable fake outputs
- Logs all interactions
- Flags dangerous behavioral patterns (downloads, pivoting, etc.)
"""

from __future__ import annotations

import logging
import shlex
import time
import uuid
from typing import Any

import requests

logger = logging.getLogger(__name__)

# ── Fake Environment State ────────────────────────────────────────────────


class FakeShell:
    """
    Simulates a basic Linux bash shell. Maintains minimal state (CWD, history)
    per session and traps dangerous commands.

    Usage::

        shell = FakeShell(session_id="uuid", ip="10.0.0.1")
        output, flag = shell.execute_command("cat /etc/passwd")
    """

    def __init__(self, session_id: str, ip: str, backend_url: str = "http://localhost:5000"):
        self.session_id = session_id
        self.ip = ip
        self.backend_url = backend_url
        self.cwd = "/home/admin"
        self.user = "admin"
        self.hostname = "prod-server-01"
        self.history = []

    def log_interaction(self, cmd: str, response: str, flag: str | None = None, detail: str | None = None) -> None:
        """Send the captured command to the backend for logging."""
        try:
            payload = {
                "session_id": self.session_id,
                "command": cmd,
                "response": response,
                "flag_raised": flag,
                "flag_detail": detail,
            }
            # Fire-and-forget logging to the backend API
            # For this MVP, we simulate it via HTTP if available, or just log locally.
            requests.post(f"{self.backend_url}/api/honeypot/log/shell", json=payload, timeout=1)
        except Exception:
            # Swallow exceptions in honeypot so attacker doesn't see them
            pass

    def get_prompt(self) -> str:
        """Return the current shell prompt."""
        folder = "~" if self.cwd == f"/home/{self.user}" else self.cwd
        return f"{self.user}@{self.hostname}:{folder}$ "

    def execute_command(self, raw_cmd: str) -> tuple[str, str | None, str | None]:
        """
        Execute a fake command.
        Returns: (output_string, flag_raised, flag_detail)
        """
        cmd = raw_cmd.strip()
        self.history.append(cmd)

        if not cmd:
            return "", None, None

        parts = shlex.split(cmd) if '"' in cmd or "'" in cmd else cmd.split()
        base = parts[0].lower()

        # Define command routers
        commands = {
            "whoami": self._cmd_whoami,
            "id": self._cmd_id,
            "uname": self._cmd_uname,
            "pwd": self._cmd_pwd,
            "ls": self._cmd_ls,
            "cd": self._cmd_cd,
            "cat": self._cmd_cat,
            "ifconfig": self._cmd_ifconfig,
            "ip": self._cmd_ip,
            "wget": self._cmd_download,
            "curl": self._cmd_download,
            "chmod": self._cmd_chmod,
            "./": self._cmd_exec,
            "sh": self._cmd_exec,
            "bash": self._cmd_exec,
            "ssh": self._cmd_pivoting,
            "ping": self._cmd_pivoting,
            "nmap": self._cmd_pivoting,
            "crontab": self._cmd_crontab,
            "sudo": self._cmd_sudo,
            "exit": self._cmd_exit,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
        }

        # Check for executions like ./exploit
        if cmd.startswith("./"):
            output, flag, detail = self._cmd_exec(parts)
        else:
            handler = commands.get(base, self._cmd_unknown)
            output, flag, detail = handler(parts)

        # Asynchronously log it
        time.sleep(0.05)  # slight realistic delay
        self.log_interaction(cmd, output, flag, detail)

        return output, flag, detail

    # ── Command Handlers ──────────────────────────────────────────────

    def _cmd_whoami(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return self.user, None, None

    def _cmd_id(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),27(sudo)", None, None

    def _cmd_uname(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return "Linux prod-server-01 5.15.0-91-generic x86_64 GNU/Linux", None, None

    def _cmd_pwd(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return self.cwd, None, None

    def _cmd_ls(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        if self.cwd == "/home/admin":
            return "documents  downloads  scripts  .ssh  .bash_history  system_backup.tar.gz", None, None
        elif self.cwd == "/":
            return "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var", None, None
        return "", None, None

    def _cmd_cd(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        if len(parts) > 1:
            target = parts[1]
            if target == "~":
                self.cwd = f"/home/{self.user}"
            elif target == "..":
                parts = self.cwd.split("/")
                self.cwd = "/" + "/".join(parts[1:-1]) if len(parts) > 2 else "/"
            elif target.startswith("/"):
                self.cwd = target
            else:
                self.cwd = f"{self.cwd}/{target}".replace("//", "/")
        return "", None, None

    def _cmd_cat(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        if len(parts) < 2:
            return "cat: missing file operand", None, None

        target = parts[1]
        if "passwd" in target:
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sshd:x:114:65534::/run/sshd:/usr/sbin/nologin\n"
                f"{self.user}:x:1000:1000:Admin:/home/{self.user}:/bin/bash",
                "PRIVILEGE_ESCALATION", "Read /etc/passwd"
            )
        elif "shadow" in target:
            return "cat: /etc/shadow: Permission denied", "PRIVILEGE_ESCALATION", "Attempted to read shadow"
        elif "id_rsa" in target or ".ssh" in target:
            return "cat: permission denied", "PIVOTING_ATTEMPT", "Attempted SSH key theft"
        return f"cat: {target}: No such file or directory", None, None

    def _cmd_ifconfig(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.1.15  netmask 255.255.255.0  broadcast 10.0.1.255\n"
            "        ether 02:42:0a:00:01:0f  txqueuelen 0  (Ethernet)",
            None, None
        )

    def _cmd_ip(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return self._cmd_ifconfig(parts)

    def _cmd_download(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        url = parts[-1] if len(parts) > 1 else "unknown"
        # Delay to simulate slow connection
        time.sleep(1.5)
        return (
            f"Resolving {url}... failed: Name or service not known.\n"
            f"wget: unable to resolve host address '{url}'",
            "ATTEMPTED_DOWNLOAD", url
        )

    def _cmd_chmod(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return "", "ATTEMPTED_EXECUTION", " ".join(parts)

    def _cmd_exec(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return "bash: permission denied: missing dependencies", "ATTEMPTED_EXECUTION", parts[0]

    def _cmd_pivoting(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        target = parts[1] if len(parts) > 1 else "unknown"
        return f"{parts[0]}: connect to {target} port 22: Connection timed out", "PIVOTING_ATTEMPT", target

    def _cmd_crontab(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return "crontab: permission denied", "PERSISTENCE_ATTEMPT", "User tried crontab"

    def _cmd_sudo(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        target = str(parts[1:]) if len(parts) > 1 else ""
        return f"[sudo] password for {self.user}: \nSorry, try again.\nsudo: 1 incorrect password attempt", "PRIVILEGE_ESCALATION", target

    def _cmd_clear(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return "\033[H\033[J", None, None

    def _cmd_history(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        out = ""
        for i, cmd in enumerate(self.history):
            out += f"  {i+1}  {cmd}\n"
        return out.strip(), None, None

    def _cmd_exit(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return "logout", None, None

    def _cmd_unknown(self, parts: list[str]) -> tuple[str, str | None, str | None]:
        return f"bash: {parts[0]}: command not found", None, None
