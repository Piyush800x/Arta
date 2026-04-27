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
        flags       = ["-Pn", "-n", "-sV", "-sC", "--open", "-T4", "--max-retries", "2", "-p-"]
        timeout_val = 300
    else:
        flags       = ["-Pn", "-n", "-sV", "-T5", "--max-retries", "1", "--max-scan-delay", "10ms"]
        timeout_val = 60

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
