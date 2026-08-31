#ifndef OARS_AI_SECURE_ENTRY_H
#define OARS_AI_SECURE_ENTRY_H

#include <stddef.h>
#include <stdint.h>

enum oars_ai_secure_entry_result {
    OARS_AI_SECURE_ENTRY_CONFIGURED = 1,
    OARS_AI_SECURE_ENTRY_CANCELED = 0,
    OARS_AI_SECURE_ENTRY_DENIED = -1,
    OARS_AI_SECURE_ENTRY_UNAVAILABLE = -2,
    OARS_AI_SECURE_ENTRY_TOO_LARGE = -3
};

int oars_ai_secure_entry(
    const uint8_t *title,
    size_t title_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *secret,
    size_t secret_cap,
    size_t *secret_len
);

#endif
