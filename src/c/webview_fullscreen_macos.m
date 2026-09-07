#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>

static id fullscreen_observer;

static NSUInteger enable_fullscreen_in_view(NSView *view) {
    NSUInteger count = 0;
    if ([view isKindOfClass:[WKWebView class]]) {
        if (@available(macOS 12.3, *)) {
            ((WKWebView *)view).configuration.preferences.elementFullscreenEnabled = YES;
        }
        count++;
    }
    for (NSView *child in view.subviews) count += enable_fullscreen_in_view(child);
    return count;
}

static void configure_fullscreen(void) {
    NSUInteger count = 0;
    for (NSWindow *window in NSApp.windows) count += enable_fullscreen_in_view(window.contentView);
    if (count > 0 && fullscreen_observer) {
        [NSNotificationCenter.defaultCenter removeObserver:fullscreen_observer];
        fullscreen_observer = nil;
    }
}

void oars_enable_webview_fullscreen(void) {
    // Native SDK creates its WebView lazily after the app start callback.
    // Observe window updates only until that view exists, then remove the observer.
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!fullscreen_observer) {
            fullscreen_observer = [NSNotificationCenter.defaultCenter
                addObserverForName:NSWindowDidUpdateNotification
                object:nil
                queue:NSOperationQueue.mainQueue
                usingBlock:^(NSNotification *notification) { configure_fullscreen(); }];
        }
        configure_fullscreen();
    });
}
