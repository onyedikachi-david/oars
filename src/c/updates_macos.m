#import <Cocoa/Cocoa.h>
#import <Sparkle/Sparkle.h>
#include "updates.h"

static OarsUpdateStatus status;
static OarsUpdateGate gate;
static void *gateContext;
static NSString *const downloadsKey = @"OarsDownloadUpdatesAutomatically";
@interface OarsUpdater : NSObject <SPUUpdaterDelegate, SPUUserDriver>
@property(nonatomic, strong) SPUUpdater *updater;
@property(nonatomic, strong) NSTimer *idleTimer;
@property(nonatomic, copy) void (^choice)(SPUUserUpdateChoice);
@property(nonatomic, copy) void (^cancelDownload)(void);
@property(nonatomic, copy) void (^resumeInstallation)(void);
@property(nonatomic, copy) void (^retryTermination)(void);
@property(nonatomic) BOOL choiceReady, installationPending, installRequested;
- (void)advanceInstallation;
- (void)clearActions;
@end
static OarsUpdater *service;

@interface OarsUpdateQuitDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) id<NSApplicationDelegate> original;
@end
static OarsUpdateQuitDelegate *quitDelegate;
@implementation OarsUpdateQuitDelegate
- (BOOL)respondsToSelector:(SEL)selector { return [super respondsToSelector:selector] || [self.original respondsToSelector:selector]; }
- (id)forwardingTargetForSelector:(SEL)selector {
    return [self.original respondsToSelector:selector] ? self.original : [super forwardingTargetForSelector:selector];
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    // Only update-initiated termination reserves the command boundary.
    // A prepared update must not take ownership of an ordinary Cmd+Q.
    if (service.installationPending && (!gate || !gate(gateContext, 1))) {
        status.state = OARS_UPDATE_BLOCKED;
        return NSTerminateCancel;
    }
    if (service.resumeInstallation) {
        void (^handler)(void) = service.resumeInstallation;
        service.resumeInstallation = nil;
        dispatch_async(dispatch_get_main_queue(), handler);
        return NSTerminateCancel;
    }
    NSApplicationTerminateReply reply = [self.original respondsToSelector:_cmd] ? [self.original applicationShouldTerminate:sender] : NSTerminateNow;
    if (reply == NSTerminateCancel && gate) gate(gateContext, 2);
    return reply;
}
@end

static void copyText(char *output, size_t capacity, NSString *text) {
    // Bound by UTF-8 bytes without splitting the final scalar.
    NSData *bytes = [text dataUsingEncoding:NSUTF8StringEncoding];
    size_t length = MIN(bytes.length, capacity - 1);
    const unsigned char *source = bytes.bytes;
    if (length < bytes.length) while (length && (source[length] & 0xc0) == 0x80) length--;
    if (length) memcpy(output, source, length);
    output[length] = 0;
}
static void setError(NSString *text) {
    status.state = OARS_UPDATE_ERROR;
    copyText(status.message, sizeof(status.message), text ?: @"Unable to update Oars. Try again.");
}
static void setNotes(NSString *text, BOOL html) {
    // Never load feed HTML into a WebView or an attributed-string HTML importer.
    // Legacy HTML is reduced to text; new Oars feeds embed plain text.
    if (html) {
        text = [text stringByReplacingOccurrencesOfString:@"(?i)</?(?:p|li|br|h[1-6])\\b[^>]*>" withString:@"\n" options:NSRegularExpressionSearch range:NSMakeRange(0, text.length)];
        text = [text stringByReplacingOccurrencesOfString:@"<[^>]*>" withString:@"" options:NSRegularExpressionSearch range:NSMakeRange(0, text.length)];
        for (NSArray *pair in @[@[@"&lt;", @"<"], @[@"&gt;", @">"], @[@"&quot;", @"\""], @[@"&#39;", @"'"], @[@"&amp;", @"&"]]) text = [text stringByReplacingOccurrencesOfString:pair[0] withString:pair[1]];
    }
    copyText(status.release_notes, sizeof(status.release_notes), [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]);
}
@implementation OarsUpdater
- (void)clearActions {
    self.choice = nil; self.choiceReady = NO; self.cancelDownload = nil;
    self.resumeInstallation = nil; self.retryTermination = nil;
    self.installationPending = NO; self.installRequested = NO;
    status.install_when_idle = 0;
    if (gate) gate(gateContext, 2);
}
- (void)advanceInstallation {
    if (!self.installRequested) return;
    if (self.choice && !self.choiceReady) {
        void (^reply)(SPUUserUpdateChoice) = self.choice;
        self.choice = nil;
        reply(SPUUserUpdateChoiceInstall);
        return;
    }
    if (!self.choice && !self.resumeInstallation && !self.retryTermination) return;
    if (!gate || !gate(gateContext, 1)) { status.state = OARS_UPDATE_BLOCKED; return; }
    self.installationPending = YES;
    status.state = OARS_UPDATE_READY;
    if (self.choice) {
        void (^reply)(SPUUserUpdateChoice) = self.choice;
        self.choice = nil; self.choiceReady = NO;
        reply(SPUUserUpdateChoiceInstall);
    } else {
        void (^resume)(void) = self.resumeInstallation ?: self.retryTermination;
        self.resumeInstallation = nil;
        resume();
    }
}
// User-driver callbacks own presentation state and one-shot reply blocks.
- (void)showUpdatePermissionRequest:(SPUUpdatePermissionRequest *)request reply:(void (^)(SUUpdatePermissionResponse *))reply {
    (void)request;
    reply([[SUUpdatePermissionResponse alloc] initWithAutomaticUpdateChecks:self.updater.automaticallyChecksForUpdates automaticUpdateDownloading:@NO sendSystemProfile:NO]);
}
- (void)showUserInitiatedUpdateCheckWithCancellation:(void (^)(void))cancellation { (void)cancellation; status.state = OARS_UPDATE_CHECKING; }
- (void)showUpdateFoundWithAppcastItem:(SUAppcastItem *)item state:(SPUUserUpdateState *)state reply:(void (^)(SPUUserUpdateChoice))reply {
    copyText(status.latest_version, sizeof(status.latest_version), item.displayVersionString);
    setNotes(item.itemDescription ?: @"", ![item.itemDescriptionFormat isEqualToString:@"plain-text"]);
    self.choice = reply;
    self.choiceReady = state.stage == SPUUserUpdateStageInstalling;
    status.state = self.choiceReady ? OARS_UPDATE_READY : OARS_UPDATE_AVAILABLE;
    if (self.installRequested) [self advanceInstallation];
    else if (!self.choiceReady && status.automatic_downloads) {
        // Route automatic downloads through this driver too, so progress and
        // cancellation use the same path as user-requested downloads.
        self.choice = nil;
        reply(SPUUserUpdateChoiceInstall);
    }
}
- (void)showUpdateReleaseNotesWithDownloadData:(SPUDownloadData *)data {
    if (data.data.length <= 128 * 1024) setNotes([[NSString alloc] initWithData:data.data encoding:NSUTF8StringEncoding] ?: @"", [data.MIMEType isEqualToString:@"text/html"]);
}
- (void)showUpdateReleaseNotesFailedToDownloadWithError:(NSError *)error { (void)error; }
- (void)showUpdateNotFoundWithError:(NSError *)error acknowledgement:(void (^)(void))reply {
    (void)error; [self clearActions]; status.state = OARS_UPDATE_IDLE; status.message[0] = 0; reply();
}
- (void)showUpdaterError:(NSError *)error acknowledgement:(void (^)(void))reply {
    [self clearActions]; setError(error.localizedDescription); reply();
}
- (void)showDownloadInitiatedWithCancellation:(void (^)(void))cancellation {
    self.cancelDownload = cancellation;
    status.downloaded_bytes = 0; status.total_bytes = 0;
    status.state = OARS_UPDATE_DOWNLOADING;
}
- (void)showDownloadDidReceiveExpectedContentLength:(uint64_t)length { status.total_bytes = length; }
- (void)showDownloadDidReceiveDataOfLength:(uint64_t)length {
    status.downloaded_bytes = UINT64_MAX - status.downloaded_bytes < length ? UINT64_MAX : status.downloaded_bytes + length;
}
- (void)showDownloadDidStartExtractingUpdate { self.cancelDownload = nil; status.state = OARS_UPDATE_VERIFYING; }
- (void)showExtractionReceivedProgress:(double)progress { (void)progress; }
- (void)showReadyToInstallAndRelaunch:(void (^)(SPUUserUpdateChoice))reply {
    self.cancelDownload = nil; self.choice = reply; self.choiceReady = YES;
    status.state = OARS_UPDATE_READY;
    [self advanceInstallation];
}
- (void)showInstallingUpdateWithApplicationTerminated:(BOOL)terminated retryTerminatingApplication:(void (^)(void))retry {
    self.retryTermination = terminated ? nil : retry;
}
- (void)showUpdateInstalledAndRelaunched:(BOOL)relaunched acknowledgement:(void (^)(void))reply { (void)relaunched; [self clearActions]; reply(); }
- (void)dismissUpdateInstallation { [self clearActions]; if (status.state != OARS_UPDATE_ERROR) status.state = OARS_UPDATE_IDLE; }
- (BOOL)updater:(SPUUpdater *)updater mayPerformUpdateCheck:(SPUUpdateCheck)check error:(NSError * __autoreleasing *)error {
    (void)updater; (void)check; (void)error;
    status.state = OARS_UPDATE_CHECKING; status.message[0] = 0;
    status.release_notes[0] = 0; status.latest_version[0] = 0;
    return YES;
}
- (BOOL)updater:(SPUUpdater *)updater shouldPostponeRelaunchForUpdate:(SUAppcastItem *)item untilInvokingBlock:(void (^)(void))handler {
    (void)updater; (void)item;
    if (!gate || !gate(gateContext, 1)) {
        self.resumeInstallation = handler; status.state = OARS_UPDATE_BLOCKED; return YES;
    }
    return NO;
}
- (BOOL)updaterShouldRelaunchApplication:(SPUUpdater *)updater { (void)updater; return YES; }
- (void)updater:(SPUUpdater *)updater didAbortWithError:(NSError *)error { (void)updater; [self clearActions]; setError(error.localizedDescription); }
- (void)updater:(SPUUpdater *)updater didFinishUpdateCycleForUpdateCheck:(SPUUpdateCheck)check error:(NSError *)error {
    (void)updater; (void)check;
    if (error) {
        [self clearActions];
        if (error.code == SUNoUpdateError || error.code == SUInstallationCanceledError) { status.state = OARS_UPDATE_IDLE; status.message[0] = 0; }
        else setError(error.localizedDescription);
    } else if (status.state == OARS_UPDATE_CHECKING) status.state = OARS_UPDATE_IDLE;
}
@end

void oars_updates_start(const char *version, OarsUpdateParse parse, OarsUpdateGate callback, void *context) {
    (void)version; (void)parse;
    if (service) return;
    memset(&status, 0, sizeof(status)); gate = callback; gateContext = context;
    NSBundle *bundle = NSBundle.mainBundle;
    if (![bundle.bundlePath.pathExtension isEqualToString:@"app"] || ![bundle objectForInfoDictionaryKey:@"SUPublicEDKey"] || ![bundle objectForInfoDictionaryKey:@"SUFeedURL"]) return;
    NSUserDefaults *preferences = NSUserDefaults.standardUserDefaults;
    if (![preferences objectForKey:downloadsKey]) {
        id previous = [preferences objectForKey:@"SUAutomaticallyUpdate"] ?: [bundle objectForInfoDictionaryKey:@"SUAutomaticallyUpdate"] ?: @YES;
        [preferences setBool:[previous boolValue] forKey:downloadsKey];
    }
    status.automatic_downloads = [preferences boolForKey:downloadsKey];
    service = [OarsUpdater new];
    service.updater = [[SPUUpdater alloc] initWithHostBundle:bundle applicationBundle:bundle userDriver:service delegate:service];
    service.updater.automaticallyDownloadsUpdates = NO;
    status.mode = 1; status.state = OARS_UPDATE_IDLE;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!service) return;
        quitDelegate = [OarsUpdateQuitDelegate new]; quitDelegate.original = NSApp.delegate; NSApp.delegate = quitDelegate;
        if (!getenv("OARS_DISABLE_UPDATE_CHECKS")) {
            NSError *error = nil;
            if (![service.updater startUpdater:&error]) setError(error.localizedDescription);
        }
        service.idleTimer = [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(NSTimer *timer) {
            (void)timer;
            if (status.install_when_idle) [service advanceInstallation];
        }];
    });
}
void oars_updates_stop(void) { [service.idleTimer invalidate]; gate = NULL; gateContext = NULL; }
void oars_updates_status(OarsUpdateStatus *out) {
    if (service) {
        status.automatic_checks = service.updater.automaticallyChecksForUpdates;
        status.can_check = service.updater.canCheckForUpdates && !service.choice && !service.cancelDownload && !service.installationPending;
        status.can_install = service.choice != nil || service.resumeInstallation != nil || service.retryTermination != nil;
        status.can_resume = status.can_install && (service.choiceReady || service.resumeInstallation || service.retryTermination);
        status.can_cancel = service.cancelDownload != nil || (status.install_when_idle && !service.installationPending);
    }
    *out = status;
}
int oars_updates_check(void) {
    OarsUpdateStatus snapshot; oars_updates_status(&snapshot);
    if (!service || !snapshot.can_check) return 0;
    status.message[0] = 0; status.state = OARS_UPDATE_CHECKING;
    [service.updater checkForUpdates]; return 1;
}
int oars_updates_preferences(int checks, int downloads) {
    if (!service) return 0;
    service.updater.automaticallyChecksForUpdates = checks != 0;
    status.automatic_downloads = downloads != 0;
    [NSUserDefaults.standardUserDefaults setBool:downloads != 0 forKey:downloadsKey];
    return 1;
}
int oars_updates_install(int when_idle) {
    if (!service || service.installationPending) return 0;
    if (!service.choice && !service.resumeInstallation && !service.retryTermination && status.state != OARS_UPDATE_DOWNLOADING && status.state != OARS_UPDATE_VERIFYING) return 0;
    if (!when_idle && (!gate || !gate(gateContext, 0))) return 0;
    service.installRequested = YES; status.install_when_idle = when_idle != 0;
    [service advanceInstallation]; return 1;
}
int oars_updates_resume(void) { return oars_updates_install(0); }
int oars_updates_cancel(void) {
    if (!service || service.installationPending) return 0;
    if (service.cancelDownload) {
        void (^cancel)(void) = service.cancelDownload;
        [service clearActions]; cancel(); status.state = OARS_UPDATE_IDLE; status.message[0] = 0; return 1;
    }
    if (status.install_when_idle) {
        status.install_when_idle = 0; service.installRequested = NO;
        if (status.state == OARS_UPDATE_BLOCKED) status.state = OARS_UPDATE_READY;
        return 1;
    }
    return 0;
}
void oars_updates_release_notes(void) {
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"https://github.com/onyedikachi-david/oars/releases"]];
}
