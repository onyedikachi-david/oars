"""Exercise the Linux notification transport against a local HTTP server."""
import hashlib
import http.server
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
HOST = r'''
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "updates.h"
static GMainLoop *loop;
static int parsed;
static int code = 1;
static int parse(void *context, const unsigned char *data, size_t len, char *out, size_t capacity) {
    (void)context; ++parsed;
    const char *valid = "{\"schema_version\":1,\"version\":\"2.0.0\"}";
    if (strlen(valid) != len || memcmp(data, valid, len)) return -1;
    snprintf(out, capacity, "2.0.0"); return 1;
}
static gboolean inspect(gpointer unused) {
    (void)unused;
    OarsUpdateStatus s; oars_updates_status(&s);
    int expect_error = atoi(getenv("EXPECT_ERROR"));
    if (s.state != OARS_UPDATE_AVAILABLE && s.state != OARS_UPDATE_ERROR) return G_SOURCE_CONTINUE;
    if (s.mode != atoi(getenv("EXPECT_MODE")) || !s.can_check) goto done;
    if (oars_updates_resume() != 0 || oars_updates_preferences(1, 1) != 0) goto done;
    if (expect_error) {
        if (s.state != OARS_UPDATE_ERROR || !s.message[0]) goto done;
    } else {
        if (s.state != OARS_UPDATE_AVAILABLE || strcmp(s.latest_version, "2.0.0") || parsed != 1) goto done;
        if (!oars_updates_preferences(0, 0)) goto done;
        oars_updates_status(&s);
        if (s.automatic_checks) goto done;
    }
    code = 0;
 done:
    oars_updates_stop(); g_main_loop_quit(loop); return G_SOURCE_REMOVE;
}
int main(void) {
    loop = g_main_loop_new(NULL, FALSE);
    oars_updates_start("1.0.0", parse, NULL, NULL);
    g_timeout_add(20, inspect, NULL);
    g_main_loop_run(loop);
    // Drain canceled callbacks after shutdown; they must not use the cleared context.
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_main_loop_unref(loop);
    return code;
}
'''

with tempfile.TemporaryDirectory(prefix="oars-linux-update-") as directory:
    root = Path(directory)
    source = root / "host.c"
    source.write_text(HOST)
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libsoup-3.0", "gio-2.0"], text=True))
    for name, response, status, mode in [
        ("archive", b'{"schema_version":1,"version":"2.0.0"}', 200, 3),
        ("homebrew", b'{"schema_version":1,"version":"2.0.0"}', 200, 2),
        ("invalid", b'not-json', 200, 3),
        ("oversized", b'x' * (128 * 1024 + 1), 200, 3),
        ("http-error", b'unavailable', 503, 3),
    ]:
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                try: self.wfile.write(response)
                except (BrokenPipeError, ConnectionResetError): pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        case = root / name
        case.mkdir()
        binary = case / ("Caskroom/oars/1/bin/oars" if mode == 2 else "oars")
        binary.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cc", "-I", str(ROOT / "src/c"),
                        f'-DOARS_UPDATE_FEED_URL="http://127.0.0.1:{server.server_port}/feed"',
                        str(source), str(ROOT / "src/c/updates_linux.c"), *flags, "-o", str(binary)], check=True)
        digest = hashlib.sha256(binary.read_bytes()).digest()
        env = dict(os.environ, XDG_CONFIG_HOME=str(case / "config"), EXPECT_MODE=str(mode), EXPECT_ERROR=str(int(name not in ("archive", "homebrew"))))
        env.pop("OARS_DISABLE_UPDATE_CHECKS", None)
        try:
            subprocess.run([str(binary)], env=env, check=True, timeout=40)
            assert hashlib.sha256(binary.read_bytes()).digest() == digest
            if name in ("archive", "homebrew"):
                assert "automatic_checks=false" in (case / "config/Oars/updates.ini").read_text()
            print("PASS:", name)
        finally:
            server.shutdown(); server.server_close()
