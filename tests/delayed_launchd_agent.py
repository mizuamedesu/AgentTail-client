#!/usr/bin/env python3
"""CI-only launchd fixture: retain the real agent lock while handling SIGTERM."""
import fcntl
from pathlib import Path
import signal
import sys
import time

state = Path(sys.argv[1])
if sys.platform != 'darwin' or not (state/'launchd-fixture-enabled').exists():
    raise SystemExit('This fixture requires an isolated Darwin lifecycle test')

def stop(_signal, _frame):
    (state/'shutdown-started').touch()
    time.sleep(3)
    (state/'shutdown-finished').touch()
    raise SystemExit(0)

with (state/'agent.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    signal.signal(signal.SIGTERM, stop)
    (state/'fixture-ready').touch()
    while True:
        signal.pause()
