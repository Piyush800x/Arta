"""
tools/ssh_runner.py — Helper to run commands and upload files on a remote Attacker VM via SSH.
"""

import paramiko
import time
from pathlib import Path


class SSHRunner:
    def __init__(self, ip: str, username: str, password: str):
        self.ip = ip
        self.username = username
        self.password = password
        
    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.ip,
            username=self.username,
            password=self.password,
            timeout=10,
        )
        return client

    def run_command(self, command: str, timeout: int = 120) -> dict:
        """Run a command remotely. Returns {stdout, stderr, returncode, timed_out}."""
        try:
            with self._connect() as client:
                stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
                out = stdout.read().decode('utf-8', errors='replace')
                err = stderr.read().decode('utf-8', errors='replace')
                returncode = stdout.channel.recv_exit_status()
                return {
                    "stdout": out,
                    "stderr": err,
                    "returncode": returncode,
                    "timed_out": False,
                }
        except Exception as e:
            err_str = str(e)
            timed_out = "timeout" in err_str.lower()
            return {
                "stdout": "",
                "stderr": f"SSH Error: {err_str}",
                "returncode": -1,
                "timed_out": timed_out,
            }

    def upload_file(self, local_path: str | Path, remote_path: str) -> bool:
        """Upload a local file to the remote path."""
        try:
            with self._connect() as client:
                sftp = client.open_sftp()
                sftp.put(str(local_path), remote_path)
                sftp.close()
                return True
        except Exception as e:
            print(f"[SSHRunner] File upload failed: {e}")
            return False

    def download_file(self, remote_path: str, local_path: str | Path) -> bool:
        """Download a remote file to the local path."""
        try:
            with self._connect() as client:
                sftp = client.open_sftp()
                sftp.get(remote_path, str(local_path))
                sftp.close()
                return True
        except Exception as e:
            print(f"[SSHRunner] File download failed: {e}")
            return False

    def run_nmap(self, target_ip: str, session_id: str, flags: list[str], timeout: int) -> str:
        """Run Nmap remotely and return the XML output as a string."""
        remote_xml_path = f"/tmp/{session_id}_nmap.xml"
        
        cmd = " ".join(["sudo", "-n", "nmap"] + flags + ["-oX", remote_xml_path, target_ip])
        # If sudo fails (requires password interactively), fallback to running without sudo
        # Since we use password auth, we can pass the password to sudo via stdin using echo
        cmd = f"echo '{self.password}' | sudo -S nmap {' '.join(flags)} -oX {remote_xml_path} {target_ip}"
        
        self.run_command(cmd, timeout=timeout)
        
        # Read the XML file content
        res = self.run_command(f"cat {remote_xml_path}", timeout=30)
        
        # Cleanup
        self.run_command(f"rm -f {remote_xml_path}", timeout=10)
        
        return res.get("stdout", "")

