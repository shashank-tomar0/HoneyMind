"""
Fake FTP Service
================
Interactive FTP Honeypot. Serves Canary/Bait files directly to the attacker.
If an attacker downloads a bait file (via wget/ftp), it triggers the IP reveal hook.
"""

import logging
import os
import requests
import tempfile
import uuid
from typing import Any

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
except ImportError:
    FTPServer = None

logger = logging.getLogger(__name__)

class HoneypotFTPHandler(FTPHandler):
    """
    Custom FTP handler to accept all credentials and log downloads.
    """
    banner = "220 Microsoft FTP Service"

    def on_connect(self):
        logger.info(f"FTP Connect: {self.remote_ip}:{self.remote_port}")
        self.session_id = str(uuid.uuid4())

    def on_login(self, username):
        logger.info(f"FTP Login Success: {username} from {self.remote_ip}")

    def on_login_failed(self, username, password):
        # We override auth anyway to let them in, but in case
        pass

    def on_file_sent(self, file_path):
        """Triggered when an attacker successfully downloads a file."""
        filename = os.path.basename(file_path)
        logger.warning(f"FTP DOWNLOAD: ip={self.remote_ip} downloaded {filename}")
        
        # Log to Backend
        try:
            payload = {
                "session_id": self.session_id,
                "command": f"RETR {filename}",
                "response": "226 Transfer complete",
                "flag_raised": "ATTEMPTED_DOWNLOAD",
                "flag_detail": filename,
            }
            requests.post("http://localhost:5000/api/honeypot/log/shell", json=payload, timeout=2)
        except Exception:
            pass


class AllowAllAuthorizer(DummyAuthorizer):
    """Bypasses actual authentication to trap all attackers."""
    def validate_authentication(self, username, password, handler):
        # Allow absolutely anything
        pass


def setup_bait_filesystem() -> str:
    """
    Create a temporary directory structure mimicking a real application server
    and populate it with canary bait files grabbed from our backend.
    """
    base_dir = tempfile.mkdtemp(prefix="ftp_honeypot_")
    
    # Create fake structure
    os.makedirs(os.path.join(base_dir, "backups"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "config"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "logs"), exist_ok=True)

    logger.info("Fetching canary bait files from internal generator...")
    
    # Attempt to fetch dynamic canary files from our Flask backend
    # If the backend is down, we just create empty dummy files
    try:
        res = requests.get("http://localhost:5000/api/canary/generate?type=xlsx&filename=db_dump_2024.xlsx", timeout=3)
        if res.status_code == 200:
            with open(os.path.join(base_dir, "backups", "db_dump_2024.xlsx"), "wb") as f:
                f.write(res.content)
        
        res = requests.get("http://localhost:5000/api/canary/generate?type=pdf&filename=network_topology.pdf", timeout=3)
        if res.status_code == 200:
            with open(os.path.join(base_dir, "config", "network_topology.pdf"), "wb") as f:
                f.write(res.content)
                
    except requests.exceptions.RequestException:
        logger.warning("Backend unreachable. Creating static dummy files for FTP.")
        with open(os.path.join(base_dir, "backups", "db_dump_2024.sql"), "w") as f:
            f.write("-- SQL Backup\n")

    return base_dir


def start_fake_ftp(port: int = 2121):
    """Start the Fake FTP Honeypot Server."""
    if not FTPServer:
        logger.error("pyftpdlib not installed. Fake FTP disabled.")
        return

    ftp_dir = setup_bait_filesystem()
    logger.info(f"FTP root directory prepared at: {ftp_dir}")

    authorizer = AllowAllAuthorizer()
    
    # We map 'anonymous' to our directory, and since validate_auth accepts anything, 
    # any username inherently maps to anonymous's permissions here.
    authorizer.add_anonymous(ftp_dir, perm="elr")

    handler = HoneypotFTPHandler
    handler.authorizer = authorizer

    server = FTPServer(('0.0.0.0', port), handler)
    logger.info(f"Fake FTP Server listening on port {port} ...")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("FTP server shutting down.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_fake_ftp()
