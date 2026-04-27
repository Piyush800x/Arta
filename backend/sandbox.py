import os
import subprocess
import textwrap
from pathlib import Path

from config import SANDBOX_DIR

# Detect platform
IS_WINDOWS = os.name == "nt"

if not IS_WINDOWS:
    import resource

    def _set_resource_limits():
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
        resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))
else:
    def _set_resource_limits():
        pass  # No-op on Windows


def _minimal_env():
    return {"PATH": os.environ.get("PATH", "")}


def run_poc(session_id: str, python_code: str, timeout: int = 120):
    session_dir = Path(SANDBOX_DIR) / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    poc_file = session_dir / "poc.py"
    poc_file.write_text(textwrap.dedent(python_code))

    try:
        result = subprocess.run(
            ["python", str(poc_file)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_minimal_env(),
            **({} if IS_WINDOWS else {"preexec_fn": _set_resource_limits})
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "timed_out": False,
        }

    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timed out.", "returncode": -1, "timed_out": True}

    finally:
        if poc_file.exists():
            poc_file.unlink()
