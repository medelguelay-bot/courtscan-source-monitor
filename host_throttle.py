"""Cross-process host pacing for one bounded monitor run; no network bypass."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import threading
import time

MIN_INTERVAL=1.0
_local={}
_lock=threading.Lock()

@contextmanager
def state(host,deadline):
    directory=os.environ.get("COURTSCAN_THROTTLE_DIR")
    if not directory:
        with _lock:
            value=_local.setdefault(host,{"next":0.0})
            yield value
        return
    path=Path(directory)/(hashlib.sha256(host.encode("utf-8")).hexdigest()+".lock")
    with open(path,"a+b") as file:
        if file.tell()==0:file.write(b" ");file.flush()
        locked=False
        try:
            while not locked:
                if time.monotonic()>=deadline:raise TimeoutError("HOST_THROTTLE")
                try:
                    file.seek(0)
                    if os.name=="nt":
                        import msvcrt
                        msvcrt.locking(file.fileno(),msvcrt.LK_NBLCK,1)
                    else:
                        import fcntl
                        fcntl.flock(file,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    locked=True
                except (BlockingIOError,OSError):time.sleep(.05)
            file.seek(1)
            raw=file.read(128)
            value=json.loads(raw) if raw.strip() else {"next":0.0}
            yield value
            file.seek(1);file.truncate();file.write(json.dumps(value).encode("ascii"));file.flush()
        finally:
            if locked:
                file.seek(0)
                if os.name=="nt":msvcrt.locking(file.fileno(),msvcrt.LK_UNLCK,1)
                else:fcntl.flock(file,fcntl.LOCK_UN)

def wait(host,deadline):
    while True:
        with state(host,deadline) as value:
            delay=max(0.0,value["next"]-time.time())
            if delay<=0:
                value["next"]=time.time()+MIN_INTERVAL
                return
        if delay>=deadline-time.monotonic():raise TimeoutError("HOST_THROTTLE")
        time.sleep(min(delay,.25))

def defer(host,seconds,deadline):
    with state(host,deadline) as value:
        value["next"]=max(value["next"],time.time()+max(0,seconds))
