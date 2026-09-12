"""Launch a packaged app outside the checkout and require a visible window."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    executable = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="oars-package-smoke-") as directory:
        env = dict(os.environ, OARS_DATA_DIR=directory + "/data")
        env.pop("NATIVE_SDK_FRONTEND_URL", None)
        with open(directory + "/launch.log", "w+") as log:
            app = subprocess.Popen([str(executable)], cwd=directory, env=env, stdout=log, stderr=log)
            try:
                if sys.platform == "darwin":
                    swift = Path(directory) / "window.swift"
                    swift.write_text('''import AppKit
let pid = Int(CommandLine.arguments[1])!
let windows = CGWindowListCopyWindowInfo([.optionAll, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
exit(windows.contains { ($0[kCGWindowOwnerPID as String] as? Int) == pid && ($0[kCGWindowLayer as String] as? Int) == 0 } ? 0 : 1)
''')
                    probe = ["swift", str(swift), str(app.pid)]
                else:
                    probe = ["xdotool", "search", "--onlyvisible", "--pid", str(app.pid)]
                deadline = time.monotonic() + 60
                visible = False
                while time.monotonic() < deadline:
                    if app.poll() is not None:
                        raise RuntimeError(f"App exited during launch: {app.returncode}")
                    if subprocess.run(probe, stdout=subprocess.DEVNULL, timeout=30).returncode == 0:
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
