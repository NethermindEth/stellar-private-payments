#!/usr/bin/env python3
"""Measure one CI phase using GNU time; preserve its exit status and output."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import threading

label, *command = sys.argv[1:]
output = Path(os.environ.get("CI_MEASUREMENTS", "measurements"))
output.mkdir(parents=True, exist_ok=True)
report = output / (label + ".time")
stop = threading.Event()
disk_peak = [shutil.disk_usage(".").used]
def sample_disk():
    while not stop.wait(1):
        disk_peak[0] = max(disk_peak[0], shutil.disk_usage(".").used)
monitor = threading.Thread(target=sample_disk, daemon=True)
monitor.start()
start = time.monotonic()
result = subprocess.run(["/usr/bin/time", "-v", "-o", str(report), *command])
stop.set()
monitor.join()
record = {"phase": label, "command": command, "seconds": time.monotonic() - start,
          "exit_code": result.returncode, "runner_disk_used_peak_bytes": disk_peak[0], "disk_free_after_bytes": shutil.disk_usage(".").free}
# GNU time reports the maximum RSS of the command, not aggregate runner memory.
for line in report.read_text().splitlines():
    if "Maximum resident set size (kbytes):" in line:
        record["command_max_rss_kib"] = int(line.rsplit(":", 1)[1])
(output / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record), flush=True)
sys.exit(result.returncode)
