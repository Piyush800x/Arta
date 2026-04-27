"""
tools/nmap_runner.py — Subprocess wrapper for nmap.

Runs nmap against the target and returns the raw XML output as a string.
"""

import subprocess
from pathlib import Path

from tools.ssh_runner import SSHRunner


def run_nmap(target_ip: str, session_dir: Path, full_scan: bool = False, attacker: dict = None, session_id: str = None) -> str:
    """
    Run nmap against target_ip.

    Args:
        target_ip:   IP address to scan.
        session_dir: Directory to write nmap.xml into.
        full_scan:   If True, scan all 65535 ports (-p-).
        attacker:    Optional dict with ip, username, password for Remote Attacker Mode.
        session_id:  Session ID string.

    Returns:
        Raw nmap XML output as a string.
    """
    xml_path = session_dir / "nmap.xml"

    if full_scan:
        # Full scan: all ports, service detection, default scripts
        flags       = ["-sS", "-Pn", "-n", "-sV", "-sC", "--open", "-T4", "--max-retries", "3", "-p-"]
        timeout_val = 1200  # 20 mins for full 65k scan
    else:
        # Lite scan: top 1000 ports, service detection
        flags       = ["-sS", "-Pn", "-n", "-sV", "-T4", "--max-retries", "2"]
        timeout_val = 300   # 5 mins for top 1000 ports + service detection

    if attacker:
        runner = SSHRunner(attacker["ip"], attacker["username"], attacker["password"])
        xml_out = runner.run_nmap(target_ip, session_id, flags, timeout_val)
        if not xml_out:
            raise RuntimeError("Remote Nmap failed or returned no XML output.")
        xml_path.write_text(xml_out)
        return xml_out

    cmd = ["nmap"] + flags + ["-oX", str(xml_path), target_ip]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_val,
    )

    if result.returncode != 0:
        raise RuntimeError(f"nmap exited with code {result.returncode}: {result.stderr}")

    return xml_path.read_text()
