import subprocess
import json
from typing import Tuple, Any

def run_ipa_healthcheck(failures_only=False) -> Tuple[int, Any]:
    cmd = ["ipa-healthcheck", "--output-type", "json"]
    if failures_only:
        cmd.append("--failures-only")
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else []
    except json.JSONDecodeError:
        data = []
    return r.returncode, data

