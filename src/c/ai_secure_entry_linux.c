#include <gtk/gtk.h>
#include <string.h>
#include "ai_secure_entry.h"

struct oars_prompt_state {
    GMainLoop *loop;
    int response;
};

static void oars_prompt_response(GtkDialog *dialog, int response, gpointer data) {
    (void)dialog;
    struct oars_prompt_state *state = data;
    state->response = response;
    g_main_loop_quit(state->loop);
}

int oars_ai_secure_entry(
    const uint8_t *title,
    size_t title_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *secret,
    size_t secret_cap,
    size_t *secret_len
) {
    if (!secret || !secret_len || secret_cap == 0 || !gtk_is_initialized()) {
        return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    }
    *secret_len = 0;
    char *caption = g_strndup((const char *)title, title_len);
    char *detail = g_strndup((const char *)message, message_len);
    if (!caption || !detail) {
        g_free(caption);
        g_free(detail);
        return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    }

    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        caption,
        NULL,
        GTK_DIALOG_MODAL,
        "Cancel",
        GTK_RESPONSE_CANCEL,
        "Save key",
        GTK_RESPONSE_ACCEPT,
        NULL
    );
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *label = gtk_label_new(detail);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(entry), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "API key");
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_box_append(GTK_BOX(content), label);
    gtk_box_append(GTK_BOX(content), entry);

    struct oars_prompt_state state = {g_main_loop_new(NULL, FALSE), GTK_RESPONSE_NONE};
    if (!state.loop) {
        gtk_window_destroy(GTK_WINDOW(dialog));
        g_free(caption);
        g_free(detail);
        return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    }
    g_signal_connect(dialog, "response", G_CALLBACK(oars_prompt_response), &state);
    gtk_window_set_default_widget(GTK_WINDOW(dialog), entry);
    gtk_window_present(GTK_WINDOW(dialog));
    gtk_widget_grab_focus(entry);
    g_main_loop_run(state.loop);

    int result = OARS_AI_SECURE_ENTRY_CANCELED;
    if (state.response == GTK_RESPONSE_ACCEPT) {
        const char *value = gtk_editable_get_text(GTK_EDITABLE(entry));
        size_t len = value ? strlen(value) : 0;
        if (len == 0) {
            result = OARS_AI_SECURE_ENTRY_CANCELED;
        } else if (len > secret_cap) {
            result = OARS_AI_SECURE_ENTRY_TOO_LARGE;
        } else {
            memcpy(secret, value, len);
            *secret_len = len;
            result = OARS_AI_SECURE_ENTRY_CONFIGURED;
        }
        gtk_editable_set_text(GTK_EDITABLE(entry), "");
    }
    gtk_window_destroy(GTK_WINDOW(dialog));
    g_main_loop_unref(state.loop);
    g_free(caption);
    g_free(detail);
    return result;
}
