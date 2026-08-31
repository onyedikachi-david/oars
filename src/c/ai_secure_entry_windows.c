#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <limits.h>
#include <string.h>
#include <wchar.h>
#include "ai_secure_entry.h"

#define OARS_AI_MAX_SECRET_BYTES 4096
#define OARS_AI_PROMPT_CLASS L"OarsAiSecureEntry"
#define OARS_AI_EDIT_ID 1001
#define OARS_AI_SAVE_ID 1002
#define OARS_AI_CANCEL_ID 1003

struct oars_prompt_context {
    const wchar_t *message;
    HWND owner;
    HWND edit;
    int result;
    wchar_t password[OARS_AI_MAX_SECRET_BYTES + 1];
};

static int oars_utf8_to_wide(const uint8_t *input, size_t len, wchar_t *output, int cap) {
    if (!input || len == 0 || len > INT_MAX || cap <= 1) return 0;
    int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)input, (int)len, output, cap - 1);
    if (written <= 0) return 0;
    output[written] = L'\0';
    return written;
}

static void oars_set_font(HWND control) {
    SendMessageW(control, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
}

static LRESULT CALLBACK oars_prompt_window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    struct oars_prompt_context *context = (struct oars_prompt_context *)GetWindowLongPtrW(window, GWLP_USERDATA);
    if (message == WM_NCCREATE) {
        CREATESTRUCTW *create = (CREATESTRUCTW *)lparam;
        context = (struct oars_prompt_context *)create->lpCreateParams;
        SetWindowLongPtrW(window, GWLP_USERDATA, (LONG_PTR)context);
    }
    if (!context) return DefWindowProcW(window, message, wparam, lparam);

    switch (message) {
        case WM_CREATE: {
            HWND label = CreateWindowExW(0, L"STATIC", context->message,
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                18, 18, 444, 52, window, NULL, NULL, NULL);
            context->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                18, 82, 444, 26, window, (HMENU)(INT_PTR)OARS_AI_EDIT_ID, NULL, NULL);
            HWND save = CreateWindowExW(0, L"BUTTON", L"Save key",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                278, 126, 88, 28, window, (HMENU)(INT_PTR)OARS_AI_SAVE_ID, NULL, NULL);
            HWND cancel = CreateWindowExW(0, L"BUTTON", L"Cancel",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                374, 126, 88, 28, window, (HMENU)(INT_PTR)OARS_AI_CANCEL_ID, NULL, NULL);
            if (!label || !context->edit || !save || !cancel) {
                context->result = OARS_AI_SECURE_ENTRY_UNAVAILABLE;
                DestroyWindow(window);
                return 0;
            }
            oars_set_font(label);
            oars_set_font(context->edit);
            oars_set_font(save);
            oars_set_font(cancel);
            SendMessageW(context->edit, EM_SETLIMITTEXT, OARS_AI_MAX_SECRET_BYTES, 0);
            SetFocus(context->edit);
            return 0;
        }
        case WM_COMMAND:
            switch (LOWORD(wparam)) {
                case OARS_AI_SAVE_ID: {
                    int length = GetWindowTextLengthW(context->edit);
                    if (length <= 0) {
                        context->result = OARS_AI_SECURE_ENTRY_CANCELED;
                    } else if (length > OARS_AI_MAX_SECRET_BYTES ||
                               GetWindowTextW(context->edit, context->password, OARS_AI_MAX_SECRET_BYTES + 1) != length) {
                        context->result = OARS_AI_SECURE_ENTRY_TOO_LARGE;
                    } else {
                        context->result = OARS_AI_SECURE_ENTRY_CONFIGURED;
                    }
                    SetWindowTextW(context->edit, L"");
                    DestroyWindow(window);
                    return 0;
                }
                case OARS_AI_CANCEL_ID:
                    context->result = OARS_AI_SECURE_ENTRY_CANCELED;
                    SetWindowTextW(context->edit, L"");
                    DestroyWindow(window);
                    return 0;
            }
            break;
        case WM_CLOSE:
            context->result = OARS_AI_SECURE_ENTRY_CANCELED;
            if (context->edit) SetWindowTextW(context->edit, L"");
            DestroyWindow(window);
            return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

static int oars_register_prompt_class(HINSTANCE instance) {
    WNDCLASSEXW window_class;
    ZeroMemory(&window_class, sizeof(window_class));
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = oars_prompt_window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    window_class.lpszClassName = OARS_AI_PROMPT_CLASS;
    if (RegisterClassExW(&window_class)) return 1;
    return GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
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
    if (!secret || !secret_len || secret_cap == 0 || secret_cap > OARS_AI_MAX_SECRET_BYTES) {
        return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    }
    *secret_len = 0;
    wchar_t caption[256];
    wchar_t detail[1024];
    if (!oars_utf8_to_wide(title, title_len, caption, 256) ||
        !oars_utf8_to_wide(message, message_len, detail, 1024)) {
        return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    }

    HINSTANCE instance = GetModuleHandleW(NULL);
    if (!instance || !oars_register_prompt_class(instance)) return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    struct oars_prompt_context context;
    ZeroMemory(&context, sizeof(context));
    context.message = detail;
    context.owner = GetActiveWindow();
    context.result = OARS_AI_SECURE_ENTRY_UNAVAILABLE;

    HWND window = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        OARS_AI_PROMPT_CLASS,
        caption,
        WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 496, 205,
        context.owner, NULL, instance, &context
    );
    if (!window) {
        SecureZeroMemory(&context, sizeof(context));
        return OARS_AI_SECURE_ENTRY_UNAVAILABLE;
    }
    if (context.owner) EnableWindow(context.owner, FALSE);
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    MSG event;
    while (IsWindow(window)) {
        int status = GetMessageW(&event, NULL, 0, 0);
        if (status <= 0) {
            context.result = OARS_AI_SECURE_ENTRY_UNAVAILABLE;
            if (IsWindow(window)) DestroyWindow(window);
            break;
        }
        if (!IsDialogMessageW(window, &event)) {
            TranslateMessage(&event);
            DispatchMessageW(&event);
        }
    }
    if (context.owner) {
        EnableWindow(context.owner, TRUE);
        SetForegroundWindow(context.owner);
    }

    int result = context.result;
    if (result == OARS_AI_SECURE_ENTRY_CONFIGURED) {
        int wide_len = (int)wcslen(context.password);
        int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, context.password, wide_len, NULL, 0, NULL, NULL);
        if (required <= 0) {
            result = OARS_AI_SECURE_ENTRY_UNAVAILABLE;
        } else if ((size_t)required > secret_cap) {
            result = OARS_AI_SECURE_ENTRY_TOO_LARGE;
        } else if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, context.password, wide_len, (char *)secret, required, NULL, NULL) != required) {
            result = OARS_AI_SECURE_ENTRY_UNAVAILABLE;
        } else {
            *secret_len = (size_t)required;
        }
    }
    SecureZeroMemory(context.password, sizeof(context.password));
    SecureZeroMemory(caption, sizeof(caption));
    SecureZeroMemory(detail, sizeof(detail));
    return result;
}
