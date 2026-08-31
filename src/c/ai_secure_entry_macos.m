#import <AppKit/AppKit.h>
#include "ai_secure_entry.h"

static NSString *oars_string(const uint8_t *bytes, size_t len) {
    return [[NSString alloc] initWithBytes:bytes length:len encoding:NSUTF8StringEncoding];
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
    if (!secret || !secret_len || secret_cap == 0 || ![NSThread isMainThread]) {
        return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    }
    *secret_len = 0;
    @autoreleasepool {
        NSString *caption = oars_string(title, title_len);
        NSString *detail = oars_string(message, message_len);
        if (!caption || !detail) return OARS_AI_SECURE_ENTRY_UNAVAILABLE;

        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = caption;
        alert.informativeText = detail;
        [alert addButtonWithTitle:@"Save key"];
        [alert addButtonWithTitle:@"Cancel"];

        NSSecureTextField *field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 360, 24)];
        field.placeholderString = @"API key";
        field.accessibilityLabel = @"Provider API key";
        alert.accessoryView = field;
        [alert.window setInitialFirstResponder:field];

        NSModalResponse response = [alert runModal];
        if (response != NSAlertFirstButtonReturn) return OARS_AI_SECURE_ENTRY_CANCELED;
        NSData *data = [field.stringValue dataUsingEncoding:NSUTF8StringEncoding];
        if (!data) return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
        if (data.length == 0) return OARS_AI_SECURE_ENTRY_CANCELED;
        if (data.length > secret_cap) return OARS_AI_SECURE_ENTRY_TOO_LARGE;
        memcpy(secret, data.bytes, data.length);
        *secret_len = data.length;
        field.stringValue = @"";
        return OARS_AI_SECURE_ENTRY_CONFIGURED;
    }
}
