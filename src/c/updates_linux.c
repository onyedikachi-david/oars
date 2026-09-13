#include "updates.h"
#include <gio/gio.h>
#include <libsoup/soup.h>
#include <string.h>
#include <unistd.h>

#ifndef OARS_UPDATE_FEED_URL
#define OARS_UPDATE_FEED_URL "https://raw.githubusercontent.com/onyedikachi-david/oars/updates/latest.json"
#endif
#define MAX_FEED (128 * 1024)
static OarsUpdateStatus status;
static OarsUpdateParse parse_feed;
static void *parse_context;
static SoupSession *session;
static SoupMessage *message;
static GCancellable *cancel;
static GInputStream *stream;
static GByteArray *body;
static GKeyFile *preferences;
static char *preferences_path;
static guint timer, deadline_timer;
static gboolean started, terminated;
static gint64 last_attempt;

static gboolean save_preferences(void) {
    g_key_file_set_boolean(preferences, "updates", "automatic_checks", status.automatic_checks);
    g_key_file_set_int64(preferences, "updates", "last_attempt", last_attempt);
    g_key_file_set_string(preferences, "updates", "latest_version", status.latest_version);
    char *data = g_key_file_to_data(preferences, NULL, NULL);
    char *parent = g_path_get_dirname(preferences_path);
    gboolean saved = g_mkdir_with_parents(parent, 0700) == 0 && g_file_set_contents(preferences_path, data, -1, NULL);
    g_free(parent); g_free(data);
    return saved;
}
static void finish(const char *error) {
    if (deadline_timer) { g_source_remove(deadline_timer); deadline_timer = 0; }
    if (started) {
        if (error) { status.state = OARS_UPDATE_ERROR; g_strlcpy(status.message, error, sizeof(status.message)); }
        status.can_check = 1;
        save_preferences();
    }
    if (stream) g_input_stream_close(stream, NULL, NULL);
    g_clear_object(&stream); g_clear_object(&message); g_clear_object(&cancel);
    if (body) { g_byte_array_unref(body); body = NULL; }
}
static void read_next(void);
static void read_complete(GObject *source, GAsyncResult *result, gpointer unused) {
    (void)unused;
    GError *error = NULL;
    GBytes *bytes = g_input_stream_read_bytes_finish(G_INPUT_STREAM(source), result, &error);
    if (!started || !bytes) {
        if (bytes) g_bytes_unref(bytes);
        g_clear_error(&error); finish("Could not check for updates. Check your connection and try again."); return;
    }
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    if (body->len + size > MAX_FEED) {
        g_bytes_unref(bytes); finish("The update response was invalid. Try again later."); return;
    }
    if (size) {
        g_byte_array_append(body, data, size); g_bytes_unref(bytes); read_next(); return;
    }
    g_bytes_unref(bytes);
    int found = parse_feed ? parse_feed(parse_context, body->data, body->len, status.latest_version, sizeof(status.latest_version)) : -1;
    if (found < 0) { finish("The update response was invalid. Try again later."); return; }
    status.state = found ? OARS_UPDATE_AVAILABLE : OARS_UPDATE_IDLE;
    status.message[0] = 0;
    finish(NULL);
}
static void read_next(void) {
    g_input_stream_read_bytes_async(stream, 4096, G_PRIORITY_DEFAULT, cancel, read_complete, NULL);
}
static void response_ready(GObject *source, GAsyncResult *result, gpointer unused) {
    (void)unused;
    GError *error = NULL;
    stream = soup_session_send_finish(SOUP_SESSION(source), result, &error);
    if (!started || !stream || soup_message_get_status(message) != SOUP_STATUS_OK) {
        g_clear_error(&error); finish("Could not check for updates. Check your connection and try again."); return;
    }
    body = g_byte_array_new(); read_next();
}
static gboolean check_deadline(gpointer unused) {
    (void)unused;
    deadline_timer = 0;
    if (cancel) g_cancellable_cancel(cancel);
    return G_SOURCE_REMOVE;
}
int oars_updates_check(void) {
    if (!started || !status.can_check) return 0;
    status.can_check = 0; status.state = OARS_UPDATE_CHECKING; status.message[0] = 0;
    last_attempt = g_get_real_time() / G_USEC_PER_SEC;
    save_preferences();
    message = soup_message_new("GET", OARS_UPDATE_FEED_URL);
    cancel = g_cancellable_new();
    deadline_timer = g_timeout_add_seconds(30, check_deadline, NULL);
    soup_session_send_async(session, message, G_PRIORITY_DEFAULT, cancel, response_ready, NULL);
    return 1;
}
static gboolean scheduled_check(gpointer unused) {
    (void)unused;
    if (started && status.automatic_checks && !g_getenv("OARS_DISABLE_UPDATE_CHECKS") &&
        (g_get_real_time() / G_USEC_PER_SEC - last_attempt >= 86400)) oars_updates_check();
    return G_SOURCE_CONTINUE;
}
void oars_updates_start(const char *version, OarsUpdateParse parser, OarsUpdateGate gate, void *context) {
    (void)version; (void)gate;
    if (started || terminated) return;
    memset(&status, 0, sizeof(status));
    parse_feed = parser; parse_context = context;
    char executable[4096] = {0};
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    status.mode = length > 0 && strstr(executable, "/Caskroom/oars/") ? 2 : 3;
    status.state = OARS_UPDATE_IDLE; status.can_check = 1; status.automatic_checks = 1;
    preferences = g_key_file_new();
    preferences_path = g_build_filename(g_get_user_config_dir(), "Oars", "updates.ini", NULL);
    g_key_file_load_from_file(preferences, preferences_path, G_KEY_FILE_NONE, NULL);
    if (g_key_file_has_key(preferences, "updates", "automatic_checks", NULL))
        status.automatic_checks = g_key_file_get_boolean(preferences, "updates", "automatic_checks", NULL);
    last_attempt = g_key_file_get_int64(preferences, "updates", "last_attempt", NULL);
    if (last_attempt > g_get_real_time() / G_USEC_PER_SEC) last_attempt = 0;
    char *cached = g_key_file_get_string(preferences, "updates", "latest_version", NULL);
    if (cached) {
        // Run cached data through the same strict version parser.
        char *feed = g_strdup_printf("{\"schema_version\":1,\"version\":\"%s\"}", cached);
        int found = parser(context, (const unsigned char *)feed, strlen(feed), status.latest_version, sizeof(status.latest_version));
        if (found > 0) status.state = OARS_UPDATE_AVAILABLE;
        g_free(feed); g_free(cached);
    }
    session = soup_session_new_with_options("timeout", 15, "user-agent", "Oars update checker", NULL);
    started = TRUE;
    timer = g_timeout_add_seconds(60, scheduled_check, NULL);
    scheduled_check(NULL);
}
void oars_updates_stop(void) {
    started = FALSE; terminated = TRUE; parse_feed = NULL; parse_context = NULL;
    if (timer) { g_source_remove(timer); timer = 0; }
    if (deadline_timer) { g_source_remove(deadline_timer); deadline_timer = 0; }
    if (cancel) g_cancellable_cancel(cancel);
    if (session) soup_session_abort(session);
    g_clear_object(&session);
    if (preferences) { g_key_file_unref(preferences); preferences = NULL; }
    g_clear_pointer(&preferences_path, g_free);
}
void oars_updates_status(OarsUpdateStatus *out) { *out = status; }
int oars_updates_preferences(int checks, int downloads) {
    if (!started || downloads) return 0;
    int previous = status.automatic_checks;
    status.automatic_checks = checks != 0;
    if (!save_preferences()) { status.automatic_checks = previous; return 0; }
    return 1;
}
int oars_updates_resume(void) { return 0; }
void oars_updates_release_notes(void) {
    g_app_info_launch_default_for_uri("https://github.com/onyedikachi-david/oars/releases", NULL, NULL);
}
