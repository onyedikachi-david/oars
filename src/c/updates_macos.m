#import <Cocoa/Cocoa.h>
#import <Sparkle/Sparkle.h>
#include "updates.h"

static OarsUpdateStatus status;
static OarsUpdateGate gate;
static void *gateContext;
@interface OarsUpdater : NSObject <SPUUpdaterDelegate>
@property(nonatomic, strong) SPUUpdater *updater;
@property(nonatomic, strong) id<SPUUserDriver> userDriver;
@property(nonatomic, copy) void (^resumeInstallation)(void);
@property(nonatomic) BOOL installationPending;
@end
static OarsUpdater *service;
@interface OarsUpdateQuitDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) id<NSApplicationDelegate> original;
@end
static OarsUpdateQuitDelegate *quitDelegate;
@implementation OarsUpdateQuitDelegate
- (BOOL)respondsToSelector:(SEL)selector {
    return [super respondsToSelector:selector] || [self.original respondsToSelector:selector];
}
- (id)forwardingTargetForSelector:(SEL)selector {
    return [self.original respondsToSelector:selector] ? self.original : [super forwardingTargetForSelector:selector];
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    if (service.installationPending && (!gate || !gate(gateContext, 1))) {
        status.state = OARS_UPDATE_BLOCKED;
        return NSTerminateCancel;
    }
    if (service.resumeInstallation) {
        // Sparkle must finish preparing its installer before it terminates us.
        void (^handler)(void) = service.resumeInstallation;
        service.resumeInstallation = nil;
        status.state = OARS_UPDATE_READY;
        dispatch_async(dispatch_get_main_queue(), handler);
        return NSTerminateCancel;
    }
    NSApplicationTerminateReply reply = [self.original respondsToSelector:_cmd] ? [self.original applicationShouldTerminate:sender] : NSTerminateNow;
    if (reply == NSTerminateCancel && gate) gate(gateContext, 2);
    return reply;
}
@end
static void setError(NSString *text) {
    status.state = OARS_UPDATE_ERROR;
    strlcpy(status.message, text.UTF8String ?: "Unable to check for updates. Try again.", sizeof(status.message));
}
@implementation OarsUpdater
- (BOOL)updater:(SPUUpdater *)updater mayPerformUpdateCheck:(SPUUpdateCheck)check error:(NSError * __autoreleasing *)error {
    (void)updater; (void)check; (void)error;
    if (status.state == OARS_UPDATE_IDLE || status.state == OARS_UPDATE_ERROR || status.state == OARS_UPDATE_AVAILABLE) {
        status.state = OARS_UPDATE_CHECKING;
        status.message[0] = 0;
    }
    return YES;
}
- (void)updater:(SPUUpdater *)updater didFindValidUpdate:(SUAppcastItem *)item {
    (void)updater;
    strlcpy(status.latest_version, item.displayVersionString.UTF8String ?: "", sizeof(status.latest_version));
    status.state = OARS_UPDATE_AVAILABLE;
}
- (void)updater:(SPUUpdater *)updater didNotFindUpdateWithError:(NSError *)error {
    (void)updater; (void)error;
    status.state = OARS_UPDATE_IDLE;
    status.message[0] = 0;
}
- (void)updater:(SPUUpdater *)updater willDownloadUpdate:(SUAppcastItem *)item withRequest:(NSMutableURLRequest *)request {
    (void)updater; (void)item; (void)request;
    status.state = OARS_UPDATE_DOWNLOADING;
}
- (void)updater:(SPUUpdater *)updater didDownloadUpdate:(SUAppcastItem *)item {
    (void)updater; (void)item;
    status.state = OARS_UPDATE_VERIFYING;
}
- (void)updater:(SPUUpdater *)updater didExtractUpdate:(SUAppcastItem *)item {
    (void)updater; (void)item;
    // Extraction is not the installer-ready boundary.
    status.state = OARS_UPDATE_VERIFYING;
}
- (void)updater:(SPUUpdater *)updater willInstallUpdate:(SUAppcastItem *)item {
    (void)updater; (void)item;
    self.installationPending = YES;
    status.state = OARS_UPDATE_READY;
}
- (BOOL)updater:(SPUUpdater *)updater shouldPostponeRelaunchForUpdate:(SUAppcastItem *)item untilInvokingBlock:(void (^)(void))handler {
    (void)updater; (void)item;
    if (!gate || !gate(gateContext, 1)) {
        self.installationPending = YES;
        self.resumeInstallation = handler;
        status.state = OARS_UPDATE_BLOCKED;
        return YES;
    }
    return NO;
}
- (BOOL)updaterShouldRelaunchApplication:(SPUUpdater *)updater {
    (void)updater;
    // Termination is gated separately, including Sparkle paths without postponement.
    return YES;
}
- (void)updater:(SPUUpdater *)updater didAbortWithError:(NSError *)error {
    (void)updater;
    self.resumeInstallation = nil;
    self.installationPending = NO;
    if (gate) gate(gateContext, 2);
    setError(error.localizedDescription);
}
- (void)updater:(SPUUpdater *)updater didFinishUpdateCycleForUpdateCheck:(SPUUpdateCheck)check error:(NSError *)error {
    (void)updater; (void)check;
    if (error) {
        self.resumeInstallation = nil;
        self.installationPending = NO;
        if (gate) gate(gateContext, 2);
        if (error.code == SUNoUpdateError || error.code == SUInstallationCanceledError) {
            status.state = OARS_UPDATE_IDLE;
            status.message[0] = 0;
        } else {
            setError(error.localizedDescription);
        }
    } else if (status.state == OARS_UPDATE_CHECKING) {
        status.state = OARS_UPDATE_IDLE;
    }
}
@end

void oars_updates_start(const char *version, OarsUpdateParse parse, OarsUpdateGate callback, void *context) {
    (void)version; (void)parse;
    if (service) return;
    memset(&status, 0, sizeof(status));
    gate = callback; gateContext = context;
    NSBundle *bundle = NSBundle.mainBundle;
    if (![bundle.bundlePath.pathExtension isEqualToString:@"app"] ||
        ![bundle objectForInfoDictionaryKey:@"SUPublicEDKey"] ||
        ![bundle objectForInfoDictionaryKey:@"SUFeedURL"]) return;
    service = [OarsUpdater new];
    service.userDriver = [[SPUStandardUserDriver alloc] initWithHostBundle:bundle delegate:nil];
    service.updater = [[SPUUpdater alloc] initWithHostBundle:bundle applicationBundle:bundle userDriver:service.userDriver delegate:service];
    status.mode = 1; status.state = OARS_UPDATE_IDLE;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!service) return;
        quitDelegate = [OarsUpdateQuitDelegate new];
        quitDelegate.original = NSApp.delegate;
        NSApp.delegate = quitDelegate;
        if (!getenv("OARS_DISABLE_UPDATE_CHECKS")) {
            NSError *error = nil;
            if (![service.updater startUpdater:&error]) setError(error.localizedDescription);
        }
    });
}
void oars_updates_stop(void) {
    // Sparkle owns the on-quit installer. Keep it alive through termination.
    gate = NULL; gateContext = NULL;
}
void oars_updates_status(OarsUpdateStatus *out) {
    if (service) {
        status.automatic_checks = service.updater.automaticallyChecksForUpdates;
        status.automatic_downloads = service.updater.automaticallyDownloadsUpdates;
        status.can_check = service.updater.canCheckForUpdates;
        status.can_resume = service.resumeInstallation != nil;
    }
    *out = status;
}
int oars_updates_check(void) {
    if (!service || !service.updater.canCheckForUpdates) return 0;
    status.message[0] = 0; status.state = OARS_UPDATE_CHECKING;
    [service.updater checkForUpdates];
    return 1;
}
int oars_updates_preferences(int checks, int downloads) {
    if (!service) return 0;
    service.updater.automaticallyChecksForUpdates = checks != 0;
    service.updater.automaticallyDownloadsUpdates = downloads != 0;
    return 1;
}
int oars_updates_resume(void) {
    if (!service.resumeInstallation || !gate || !gate(gateContext, 1)) return 0;
    void (^handler)(void) = service.resumeInstallation;
    service.resumeInstallation = nil;
    status.state = OARS_UPDATE_READY;
    handler();
    return 1;
}
void oars_updates_release_notes(void) {
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"https://github.com/onyedikachi-david/oars/releases"]];
}
