#!/usr/bin/env python3
"""Measure one CI phase using GNU time; preserve its exit status and output."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

label, *command = sys.argv[1:]
output = Path(os.environ.get("CI_MEASUREMENTS", "measurements"))
output.mkdir(parents=True, exist_ok=True)
report = output / (label + ".time")
start = time.monotonic()
result = subprocess.run(["/usr/bin/time", "-v", "-o", str(report), *command])
record = {"phase": label, "command": command, "seconds": time.monotonic() - start,
          "exit_code": result.returncode, "disk_free_after_bytes": shutil.disk_usage(".").free}
# GNU time reports the maximum RSS of the command, not aggregate runner memory.
for line in report.read_text().splitlines():
    if "Maximum resident set size (kbytes):" in line:
        record["command_max_rss_kib"] = int(line.rsplit(":", 1)[1])
(output / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record), flush=True)
sys.exit(result.returncode)
