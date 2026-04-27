"""
sandbox.py — Safe subprocess execution for PoC exploit scripts.

No gVisor, so we layer these protections manually:
  - Minimal environment (no HOME, restricted PATH)
  - Strict timeout
  - Subprocess output captured, never echoed to shell
  - resource limits applied before exec (CPU, memory, process count)
  - PoC scripts isolated to a per-session tmp directory
"""

import os
import subprocess
import textwrap
import sys
from pathlib import Path

from tools.ssh_runner import SSHRunner

try:
    import resource
except ImportError:
    resource = None

from config import SANDBOX_DIR


def _set_resource_limits() -> None:
    """Called by subprocess preexec_fn to cap resource usage."""
    if resource is None:
        return
    resource.setrlimit(resource.RLIMIT_CPU,   (30, 30))       # 30s CPU
    resource.setrlimit(resource.RLIMIT_AS,    (512 * 1024**2, 512 * 1024**2))  # 512 MB RAM
    resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))       # max 10 child processes


def _minimal_env() -> dict[str, str]:
    """Stripped-down environment so PoCs can't read sensitive host vars."""
    if sys.platform == "win32":
        # Keep minimal environment but PATH needs to be valid for Windows
        return {"PATH": os.environ.get("PATH", "")}
    return {"PATH": "/usr/bin:/usr/local/bin"}


def run_poc(session_id: str, python_code: str, timeout: int = 120, attacker: dict = None) -> dict:
    """
    Write python_code to a sandboxed temp file and execute it.

    Returns:
        { "stdout": str, "stderr": str, "returncode": int, "timed_out": bool }
    """
    session_dir = Path(SANDBOX_DIR) / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    poc_file = session_dir / "poc.py"
    poc_file.write_text(textwrap.dedent(python_code))

    if attacker:
        runner = SSHRunner(attacker["ip"], attacker["username"], attacker["password"])
        remote_script_path = f"/tmp/{session_id}_poc.py"
        runner.upload_file(poc_file, remote_script_path)
        
        # Run python3 remotely
        res = runner.run_command(f"python3 {remote_script_path}", timeout=timeout)
        runner.run_command(f"rm -f {remote_script_path}", timeout=10)
        return res

    timed_out = False
    python_cmd = "python" if sys.platform == "win32" else "python3"
    
    # preexec_fn is only supported on POSIX
    kwargs = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "env": _minimal_env(),
    }
    
    if sys.platform != "win32" and resource is not None:
        kwargs["preexec_fn"] = _set_resource_limits

    try:
        result = subprocess.run(
            [python_cmd, str(poc_file)],
            **kwargs
        )
        return {
            "stdout":     result.stdout,
            "stderr":     result.stderr,
            "returncode": result.returncode,
            "timed_out":  False,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timed out.", "returncode": -1, "timed_out": True}
    finally:
        # Always clean up generated PoC file
        if poc_file.exists():
            poc_file.unlink()


def cleanup_session(session_id: str) -> None:
    """Remove sandbox directory after the session completes."""
    session_dir = Path(SANDBOX_DIR) / session_id
    if session_dir.exists():
        for f in session_dir.iterdir():
            if f.is_file():
                f.unlink()
        session_dir.rmdir()
