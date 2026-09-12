"""Launch a packaged app outside the checkout and require an app window."""

import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def mac_has_window(pid):
    """Read CoreGraphics directly so a cold Swift compiler cannot time out."""
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    pointer = ctypes.c_void_p
    cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cg.CGWindowListCopyWindowInfo.restype = pointer
    cf.CFArrayGetCount.argtypes = [pointer]
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFArrayGetValueAtIndex.argtypes = [pointer, ctypes.c_long]
    cf.CFArrayGetValueAtIndex.restype = pointer
    cf.CFDictionaryGetValue.argtypes = [pointer, pointer]
    cf.CFDictionaryGetValue.restype = pointer
    cf.CFNumberGetValue.argtypes = [pointer, ctypes.c_long, pointer]
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFRelease.argtypes = [pointer]
    cf.CFRelease.restype = None
    owner_key = pointer.in_dll(cg, "kCGWindowOwnerPID")
    layer_key = pointer.in_dll(cg, "kCGWindowLayer")

    def number(window, key):
        ref = cf.CFDictionaryGetValue(window, key)
        value = ctypes.c_int()
        return value.value if ref and cf.CFNumberGetValue(ref, 9, ctypes.byref(value)) else None

    windows = cg.CGWindowListCopyWindowInfo(0, 0)
    if not windows:
        return False
    try:
        for index in range(cf.CFArrayGetCount(windows)):
            window = cf.CFArrayGetValueAtIndex(windows, index)
            if number(window, owner_key) == pid and number(window, layer_key) == 0:
                return True
        return False
    finally:
        cf.CFRelease(windows)


def main():
    executable = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="oars-package-smoke-") as directory:
        env = dict(os.environ, OARS_DATA_DIR=directory + "/data")
        env.pop("NATIVE_SDK_FRONTEND_URL", None)
        with open(directory + "/launch.log", "w+") as log:
            app = subprocess.Popen([str(executable)], cwd=directory, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 60
                visible = False
                while time.monotonic() < deadline:
                    if app.poll() is not None:
                        raise RuntimeError(f"App exited during launch: {app.returncode}")
                    visible_now = mac_has_window(app.pid) if sys.platform == "darwin" else subprocess.run(
                        ["xdotool", "search", "--onlyvisible", "--pid", str(app.pid)],
                        stdout=subprocess.DEVNULL, timeout=10).returncode == 0
                    if visible_now:
                        visible = True
                        break
                    time.sleep(1)
                if not visible:
                    raise RuntimeError("No app window was created")
                time.sleep(10)
                if app.poll() is not None:
                    raise RuntimeError(f"App exited after showing its window: {app.returncode}")
                print("Packaged app created an app window and remained running.")
            finally:
                if app.poll() is None:
                    app.terminate()
                    try:
                        app.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        app.kill()
                        app.wait()
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
