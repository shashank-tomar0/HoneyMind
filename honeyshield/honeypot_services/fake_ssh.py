"""
Fake SSH Service
================
Interactive SSH Honeypot. 
Simulates realistic authentication delays. Admits attackers after a few
attempts, trapping them in the Fake Shell. Logs all session activity.
"""

import socket
import threading
import time
import random
import uuid
import logging
from typing import Any

try:
    import paramiko
except ImportError:
    paramiko = None

from honeyshield.honeypot_services.fake_shell import FakeShell

logger = logging.getLogger(__name__)

# Fake SSH Key (Generated on the fly in prod usually, hardcoded for structural setup)
HOST_KEY = paramiko.RSAKey.generate(2048) if paramiko else None


class FakeSSHServer(paramiko.ServerInterface):
    """
    Paramiko SSH Server Interface that intentionally validates passwords
    after a random number of attempts to trap attackers.
    """

    def __init__(self, ip: str, session_id: str):
        self.event = threading.Event()
        self.ip = ip
        self.session_id = session_id
        self.attempt_count = 0
        self.grant_threshold = random.randint(2, 4)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.attempt_count += 1
        
        # Simulate realistic SSH crypto delay
        time.sleep(random.uniform(1.0, 2.5))

        logger.info(f"SSH Auth Attempt: ip={self.ip} user={username} pass={password}")

        if self.attempt_count >= self.grant_threshold:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return 'password'

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True


def handle_ssh_connection(client_sock: socket.socket, addr: tuple):
    """Handle an inbound SSH connection."""
    ip, port = addr
    session_id = str(uuid.uuid4())
    logger.info(f"New SSH connection from {ip}:{port}")

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(HOST_KEY)
    
    server = FakeSSHServer(ip, session_id)
    
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        logger.error("SSH negotiation failed.")
        return

    # Wait for the attacker to authenticate
    channel = transport.accept(30)
    if channel is None:
        logger.info(f"SSH client {ip} dropped before establishing channel.")
        return

    server.event.wait(10)
    if not server.event.is_set():
        logger.info(f"SSH client {ip} dropped shell request.")
        return

    # ── Enter Fake Interactive Shell ──────────────
    
    channel.send("\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
    channel.send(" * Documentation:  https://help.ubuntu.com\r\n")
    channel.send(" * Management:     https://landscape.canonical.com\r\n")
    channel.send(" * Support:        https://ubuntu.com/advantage\r\n\r\n")
    
    shell = FakeShell(session_id, ip)

    try:
        while True:
            channel.send(shell.get_prompt())
            
            cmd_buffer = ""
            while True:
                char = channel.recv(1)
                if not char:
                    raise EOFError
                
                char = char.decode('utf-8', errors='ignore')
                if char == '\r' or char == '\n':
                    channel.send("\r\n")
                    break
                elif char == '\x03': # Ctrl+C
                    channel.send("^C\r\n")
                    cmd_buffer = ""
                    break
                elif char == '\x04': # Ctrl+D
                    raise EOFError
                elif char in ('\x08', '\x7f'): # Backspace
                    if len(cmd_buffer) > 0:
                        cmd_buffer = cmd_buffer[:-1]
                        channel.send("\x08 \x08")
                else:
                    cmd_buffer += char
                    channel.send(char)

            if cmd_buffer.strip():
                output, flag, detail = shell.execute_command(cmd_buffer)
                if output:
                    # Fix newlines in output for paramiko
                    output = output.replace('\n', '\r\n')
                    channel.send(f"{output}\r\n")
                
                if output == "logout":
                    break

    except EOFError:
        logger.info(f"SSH client {ip} disconnected naturally.")
    except Exception as e:
        logger.error(f"SSH connection error for {ip}: {e}")
    finally:
        channel.close()
        transport.close()


def start_fake_ssh(port: int = 2222):
    """Start the Fake SSH Honeypot Server."""
    if not paramiko:
        logger.error("Paramiko not installed. Fake SSH disabled.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(100)
    
    logger.info(f"Fake SSH Server listening on port {port} ...")

    while True:
        client_sock, addr = sock.accept()
        t = threading.Thread(target=handle_ssh_connection, args=(client_sock, addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_fake_ssh()
