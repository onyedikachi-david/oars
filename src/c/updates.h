#ifndef OARS_UPDATES_H
#define OARS_UPDATES_H
#include <stddef.h>
#include <stdint.h>
/* All functions and callbacks run on the native UI thread. */
enum { OARS_UPDATE_UNAVAILABLE, OARS_UPDATE_IDLE, OARS_UPDATE_CHECKING,
       OARS_UPDATE_AVAILABLE, OARS_UPDATE_DOWNLOADING, OARS_UPDATE_VERIFYING,
       OARS_UPDATE_READY, OARS_UPDATE_BLOCKED, OARS_UPDATE_ERROR };
typedef struct {
    int mode; /* 0: development/unavailable, 1: Sparkle, 2: Linux Homebrew, 3: Linux archive */
    int state, automatic_checks, automatic_downloads, can_check, can_resume;
    int can_install, can_cancel, install_when_idle;
    uint64_t downloaded_bytes, total_bytes;
    char release_notes[4096];
    char latest_version[64];
    char message[384];
} OarsUpdateStatus;
typedef int (*OarsUpdateParse)(void *, const unsigned char *, size_t, char *, size_t);
/* action 0 queries activity, 1 reserves restart, 2 cancels the reservation. */
typedef int (*OarsUpdateGate)(void *, int);
void oars_updates_start(const char *, OarsUpdateParse, OarsUpdateGate, void *);
void oars_updates_stop(void);
void oars_updates_status(OarsUpdateStatus *);
int oars_updates_check(void);
int oars_updates_preferences(int, int);
int oars_updates_resume(void);
int oars_updates_install(int when_idle);
int oars_updates_cancel(void);
void oars_updates_release_notes(void);
#endif
