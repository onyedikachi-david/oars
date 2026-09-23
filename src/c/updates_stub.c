#include "updates.h"
#include <string.h>
void oars_updates_start(const char *v, OarsUpdateParse p, OarsUpdateGate g, void *c) { (void)v; (void)p; (void)g; (void)c; }
void oars_updates_stop(void) {}
void oars_updates_status(OarsUpdateStatus *s) { memset(s, 0, sizeof(*s)); }
int oars_updates_check(void) { return 0; }
int oars_updates_preferences(int c, int d) { (void)c; (void)d; return 0; }
int oars_updates_resume(void) { return 0; }
void oars_updates_release_notes(void) {}

int oars_updates_install(int when_idle) { (void)when_idle; return 0; }
int oars_updates_cancel(void) { return 0; }
