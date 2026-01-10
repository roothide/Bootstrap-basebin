
#define RESIGNED_SYSROOT_PATH jbroot(@"/.sysroot")

static NSArray* ResignList = @[
    @"/sbin/launchd",
    @"/usr/libexec/xpcproxy",
    @"/System/Library/CoreServices/SpringBoard.app/SpringBoard",
    @"/usr/bin/powerlogHelperd",
    @"/usr/sbin/spindump",
    @"/usr/sbin/cfprefsd",
    @"/usr/libexec/lsd",
    @"/usr/libexec/transitd",
    /* more daemons */
    @"/usr/libexec/nfcd",
    @"/usr/libexec/replayd",
    @"/usr/libexec/audiomxd", //ios17+only
    @"/usr/sbin/mediaserverd",
    @"/usr/libexec/backboardd",
    @"/usr/libexec/runningboardd",
    @"/usr/libexec/thermalmonitord",
    @"/Applications/MediaRemoteUI.app/MediaRemoteUI",
    @"/System/Library/PrivateFrameworks/Pasteboard.framework/Support/pasted",
    @"/System/Library/PrivateFrameworks/ChronoCore.framework/Support/chronod",
    @"/System/Library/PrivateFrameworks/TelephonyUtilities.framework/callservicesd",

];

int ResignSystemExecutables();
