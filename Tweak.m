// HuskJITKick - sideload dylib (no jailbreak)
// What it does:
//   1. Checks whether this process already has JIT (CS_DEBUGGED set by a debugger).
//   2. If not, asks StikDebug to attach via its URL scheme (max 2 tries per launch).
//   3. If still not enabled, shows a diagnostic (e.g. get-task-allow stripped by the signer).
// What it can NOT do: grant JIT by itself. The kernel only allows it when a debugger
// is attached (or via jailbreak/TrollStore). This just automates asking for it.

#import <UIKit/UIKit.h>
#import <sys/mman.h>
#import <unistd.h>

#ifndef MAP_JIT
#define MAP_JIT 0x800
#endif
#define CS_DEBUGGED 0x10000000
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

static int gAttempts = 0;
static BOOL gAlertShown = NO;

static BOOL JITEnabled(void) {
    int flags = 0;
    if (csops(getpid(), 0 /* CS_OPS_STATUS */, &flags, sizeof(flags)) != 0) return NO;
    return (flags & CS_DEBUGGED) != 0;
}

// Extra probe: can we map MAP_JIT memory at all (non-TXM path)?
static BOOL MapJITWorks(void) {
    void *p = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (p == MAP_FAILED) return NO;
    munmap(p, 0x4000);
    return YES;
}

// Does the signed provisioning profile still contain get-task-allow?
// (Many signers strip it -> debugger can never attach -> no JIT.)
static BOOL ProfileHasGetTaskAllow(void) {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    NSData *d = path ? [NSData dataWithContentsOfFile:path] : nil;
    if (!d) return NO;
    NSData *key = [@"get-task-allow" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange r = [d rangeOfData:key options:0 range:NSMakeRange(0, d.length)];
    if (r.location == NSNotFound) return NO;
    NSData *tail = [d subdataWithRange:NSMakeRange(r.location, MIN((NSUInteger)64, d.length - r.location))];
    NSString *s = [[NSString alloc] initWithData:tail encoding:NSISOLatin1StringEncoding];
    return [s containsString:@"<true/>"];
}

static void ShowAlert(NSString *msg) {
    if (gAlertShown) return;
    gAlertShown = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *w = nil;
        for (UIScene *sc in UIApplication.sharedApplication.connectedScenes)
            if ([sc isKindOfClass:UIWindowScene.class])
                for (UIWindow *x in ((UIWindowScene *)sc).windows) if (x.isKeyWindow) w = x;
        UIViewController *vc = w.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"JIT"
                                message:msg preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:a animated:YES completion:nil];
    });
}

static void TryEnableJIT(void) {
    if (JITEnabled()) { NSLog(@"[HuskJITKick] JIT already enabled"); return; }
    if (gAttempts >= 2) {
        NSString *why = ProfileHasGetTaskAllow()
          ? @"JIT is still off. Check: StikDebug has your pairing file, LocalDevVPN is connected, Developer Mode is on."
          : @"JIT can't work: the signing profile has no get-task-allow. Re-sign with a development certificate/profile that keeps it (e.g. Sideloadly with a free Apple ID).";
        ShowAlert(why);
        return;
    }
    gAttempts++;
    NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
    NSArray *schemes = @[@"stikjit", @"stikdebug"];
    for (NSString *s in schemes) {
        NSURL *u = [NSURL URLWithString:
            [NSString stringWithFormat:@"%@://enable-jit?bundle-id=%@", s, bid]];
        __block BOOL opened = NO;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIApplication.sharedApplication openURL:u options:@{} completionHandler:^(BOOL ok) {
                opened = ok; dispatch_semaphore_signal(sem);
            }];
        });
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
        if (opened) { NSLog(@"[HuskJITKick] asked %@ to enable JIT", s); return; }
    }
    ShowAlert(@"StikDebug is not installed (or its URL scheme is blocked).");
}

__attribute__((constructor))
static void HuskJITKickInit(void) {
    NSLog(@"[HuskJITKick] loaded. JIT=%d MAP_JIT=%d get-task-allow=%d",
          JITEnabled(), MapJITWorks(), ProfileHasGetTaskAllow());
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
        queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) {
            // small delay so the app (and its own JIT flow) settles first
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                           dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ TryEnableJIT(); });
        }];
}
