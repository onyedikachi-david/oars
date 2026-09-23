"""Exercise the real Sparkle download, signature checks, quit gate and installer.

Only temporary app bundles, a loopback HTTP server and a temporary signing key
are used. No release key or installed Oars app is involved.
"""
import base64
import http.server
import importlib.util
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPARKLE = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("feeds", ROOT / "scripts/generate-update-feeds.py")
feeds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feeds)
HOST = r'''
#import <Cocoa/Cocoa.h>
#include "updates_macos.m"
static int testGate(void *context, int action) {
    (void)context;
    if (action == 2) return 1;
    BOOL allowed = [[NSFileManager defaultManager] fileExistsAtPath:@(getenv("OARS_TEST_ALLOW"))];
    if (action == 1) { printf("GATE %d\n", allowed); fflush(stdout); }
    return allowed;
}
int main(void) {
    @autoreleasepool {
        if ([[NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] isEqualToString:@"2.0.0"]) {
            [@"ok" writeToFile:[NSBundle.mainBundle objectForInfoDictionaryKey:@"OarsTestRelaunchMarker"] atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            return 0;
        }
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        oars_updates_start("1.0.0", NULL, testGate, NULL);
        __block BOOL requested = NO;
        __block int previous = -1;
        __block BOOL scheduled = NO;
        [NSTimer scheduledTimerWithTimeInterval:0.2 repeats:YES block:^(NSTimer *timer) {
            (void)timer;
            OarsUpdateStatus snapshot;
            oars_updates_status(&snapshot);
            if (!requested && snapshot.can_check) {
                requested = YES;
                [service.updater checkForUpdatesInBackground];
            }
            if (snapshot.state != previous) {
                previous = snapshot.state;
                printf("STATE %d %s\n", snapshot.state, snapshot.message); fflush(stdout);
            }
            if (snapshot.downloaded_bytes > 0) { printf("BYTES %llu\n", (unsigned long long)snapshot.downloaded_bytes); fflush(stdout); }
            if (getenv("OARS_TEST_CANCEL") && snapshot.can_cancel && snapshot.downloaded_bytes > 0) {
                if (!oars_updates_cancel()) exit(10);
                OarsUpdateStatus canceled; oars_updates_status(&canceled);
                if (canceled.install_when_idle || canceled.can_cancel) exit(11);
                printf("CANCELED\n"); fflush(stdout); [timer invalidate];
            } else if (snapshot.can_resume && !scheduled) {
                if (strstr(snapshot.release_notes, "Fixture release notes") == NULL) exit(12);
                // A ready download cannot veto an ordinary quit while busy.
                if ([quitDelegate applicationShouldTerminate:NSApp] != NSTerminateNow) exit(16);
                if (getenv("OARS_TEST_RESUME")) {
                    if ([[NSFileManager defaultManager] fileExistsAtPath:@(getenv("OARS_TEST_ALLOW"))]) {
                        if (!oars_updates_resume()) exit(13);
                        scheduled = YES;
                    } else {
                        if (oars_updates_resume()) exit(14);
                        printf("WAITING_FOR_USER\n"); fflush(stdout);
                    }
                } else {
                    if (!oars_updates_install(1)) exit(15);
                    if (!oars_updates_cancel()) exit(17);
                    OarsUpdateStatus canceled; oars_updates_status(&canceled);
                    if (canceled.install_when_idle || !canceled.can_resume) exit(18);
                    if (!oars_updates_install(1)) exit(19);
                    printf("SCHEDULED\n"); fflush(stdout);
                    scheduled = YES;
                    // No UI polling drives the update after scheduling it.
                    [timer invalidate];
                }
            }
        }];
        [NSApp run];
    }
}
'''


def wait_for(predicate, message, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise AssertionError(message)


def run_case(directory, public_key, private_key, corrupt=False, mode="idle"):
    name = "invalid" if corrupt else mode
    case = directory / name
    served = case / "served"
    served.mkdir(parents=True)
    requests = []

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(served), **kwargs)
        def log_message(self, *_):
            pass
        def copyfile(self, source, output):
            if mode != "cancel":
                return super().copyfile(source, output)
            try:
                while chunk := source.read(16384):
                    output.write(chunk); output.flush(); time.sleep(0.01)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def do_GET(self):
            requests.append(self.path)
            super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    bundle_id = "app.getoars.test." + uuid.uuid4().hex
    app = case / "installed/OarsTest.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Frameworks").mkdir()
    shutil.copy2(directory / "host", app / "Contents/MacOS/OarsTest")
    subprocess.run(["ditto", str(SPARKLE / "Sparkle.framework"), str(app / "Contents/Frameworks/Sparkle.framework")], check=True)
    info = {
        "OarsTestRelaunchMarker": str(case / "relaunched"),
        "CFBundleIdentifier": bundle_id, "CFBundleName": "Oars updater test",
        "CFBundleExecutable": "OarsTest", "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1.0.0", "CFBundleShortVersionString": "1.0.0",
        "LSMinimumSystemVersion": "11.0", "SUPublicEDKey": public_key,
        "SUFeedURL": url + "appcast.xml", "SUEnableAutomaticChecks": True,
        "SUAutomaticallyUpdate": True, "SUVerifyUpdateBeforeExtraction": True,
        "SURequireSignedFeed": True,
        # This exception exists only in these disposable test bundles.
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    update = case / "new/OarsTest.app"
    update.parent.mkdir()
    subprocess.run(["ditto", str(app), str(update)], check=True)
    info.update(CFBundleVersion="2.0.0", CFBundleShortVersionString="2.0.0")
    (update / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    for bundle in (app, update):
        subprocess.run(["codesign", "--force", "--sign", "-", str(bundle)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    archive = served / "OarsTest-2.0.0.zip"
    subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(update), str(archive)], check=True)
    if corrupt:
        feeds.assert_signing_key(SPARKLE, private_key, public_key)
        wrong_key = base64.b64encode(os.urandom(32)).decode()
        try:
            feeds.assert_signing_key(SPARKLE, wrong_key, public_key)
        except ValueError:
            print("PASS: publisher rejects a mismatched signing key")
        else:
            raise AssertionError("Publisher accepted the wrong signing key")
    archive.with_suffix(".txt").write_text("Fixture release notes: verified in-app updates.")
    generated = subprocess.run([str(SPARKLE / "bin/generate_appcast"), "--ed-key-file", "-", "--download-url-prefix", url, "--embed-release-notes", str(served)], input=private_key, text=True, capture_output=True)
    if generated.returncode:
        print((generated.stdout + generated.stderr).replace(private_key.strip(), "[redacted]"))
        generated.check_returncode()
    if corrupt:
        data = bytearray(archive.read_bytes())
        data[len(data) // 2] ^= 1
        archive.write_bytes(data)
    allowed, relaunched = case / "allow-restart", case / "relaunched"
    env = dict(os.environ, OARS_TEST_ALLOW=str(allowed), OARS_TEST_RELAUNCH=str(relaunched))
    env.pop("OARS_DISABLE_UPDATE_CHECKS", None)
    if mode == "cancel": env["OARS_TEST_CANCEL"] = "1"
    if mode == "resume": env["OARS_TEST_RESUME"] = "1"
    log_path = case / "host.log"
    proc = None
    try:
        with log_path.open("w") as log:
            proc = subprocess.Popen([str(app / "Contents/MacOS/OarsTest")], cwd=case, env=env, stdout=log, stderr=log)
        wait_for(lambda: any(path.endswith(".zip") for path in requests), "Sparkle did not request the update archive")
        if corrupt:
            wait_for(lambda: "STATE 8" in log_path.read_text(), "Tampered update was not reported as an error")
            assert plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleVersion"] == "1.0.0"
            assert not relaunched.exists()
            print("PASS: tampered archive rejected before installation")
        elif mode == "cancel":
            wait_for(lambda: "CANCELED" in log_path.read_text(), "Download was not canceled")
            assert not relaunched.exists()
            assert plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleVersion"] == "1.0.0"
            print("PASS: real download progress and cancellation leave the installed version intact")
        else:
            marker = "WAITING_FOR_USER" if mode == "resume" else "SCHEDULED"
            wait_for(lambda: marker in log_path.read_text(), "Update did not reach the install choice")
            assert proc.poll() is None, "Busy app was terminated"
            assert plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleVersion"] == "1.0.0"
            allowed.write_text("idle")
            wait_for(lambda: relaunched.exists(), "Verified update was not installed and relaunched", timeout=120)
            assert plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleVersion"] == "2.0.0"
            print(f"PASS: {mode} choice blocks busy restart, then installs and relaunches a signed update")
    except Exception:
        print(log_path.read_text() if log_path.exists() else "No updater log")
        raise
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        server.shutdown(); server.server_close()
        subprocess.run(["defaults", "delete", bundle_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cache = Path.home() / "Library/Caches" / bundle_id
        if cache.exists(): shutil.rmtree(cache)


account = "app.getoars.test-key." + uuid.uuid4().hex
try:
    with tempfile.TemporaryDirectory(prefix="oars-sparkle-test-") as temp:
        directory = Path(temp)
        subprocess.run([str(SPARKLE / "bin/generate_keys"), "--account", account], check=True, stdout=subprocess.DEVNULL)
        public_key = subprocess.check_output([str(SPARKLE / "bin/generate_keys"), "--account", account, "-p"], text=True).strip()
        key_file = directory / "private-key"
        subprocess.run([str(SPARKLE / "bin/generate_keys"), "--account", account, "-x", str(key_file)], check=True, stdout=subprocess.DEVNULL)
        key_file.chmod(0o600)
        private_key = key_file.read_text()
        source = directory / "host.m"
        source.write_text(HOST)
        subprocess.run(["clang", "-fobjc-arc", "-fblocks", "-mmacosx-version-min=11.0", "-I", str(ROOT / "src/c"), "-F", str(SPARKLE),
                        "-framework", "Sparkle", "-framework", "Cocoa", "-Wl,-rpath,@executable_path/../Frameworks", str(source), "-o", str(directory / "host")], check=True)
        run_case(directory, public_key, private_key, corrupt=True)
        run_case(directory, public_key, private_key, mode="idle")
        run_case(directory, public_key, private_key, mode="resume")
        run_case(directory, public_key, private_key, mode="cancel")
finally:
    subprocess.run(["security", "delete-generic-password", "-a", account], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
