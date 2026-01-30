#ifdef __OBJC__
#include <Foundation/Foundation.h>
#endif
#include <sys/types.h>
#include <limits.h>
#include <spawn.h>
#include "filelog.h"
#include "_ASSERT.h"

extern char*const* environ;

void enableCommLog(void* debugLog, void* errorLog);

#define JETSAM_DEFAULT_MULTIPLIER 3
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE 0x48
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE 0x4C

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

extern int posix_spawnattr_set_launch_type_np(const posix_spawnattr_t *attr, uint8_t launch_type) __API_AVAILABLE(macos(13.0), ios(16.0), tvos(16.0), watchos(9.0));
extern int posix_spawnattr_getmacpolicyinfo_np(const posix_spawnattr_t * __restrict attr, const char *policyname, void **datap, size_t *datalenp);

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
extern int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *__restrict, int *__restrict);
extern int posix_spawnattr_setexceptionports_np(posix_spawnattr_t *__restrict, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t);

int spawn(const char* path, char*const* argv, char*const* envp, void(^pid_out)(pid_t), void(^std_out)(char*,int), void(^err_out)(char*,int));

#ifdef __OBJC__
int spawn_root(NSString* path, NSArray* args, __strong NSString** stdOut, __strong NSString** stdErr);
int spawn_bootstrap_binary(char*const* argv, __strong NSString** stdOut, __strong NSString** stdErr);
#endif

pid_t get_real_ppid();

bool launchctl_support();

int requireJIT();

bool proc_traced(pid_t pid);
bool proc_debugged(pid_t pid);
int proc_get_status(int pid);
pid_t proc_get_ppid(pid_t pid);
int proc_get_pidversion(pid_t pid);
int proc_paused(pid_t pid, bool* paused);
char* proc_get_path(pid_t pid, char buffer[PATH_MAX]);
char* proc_get_identifier(pid_t pid, char buffer[255]);

int proc_hook_dyld(pid_t pid);
int proc_enable_jit(pid_t pid, bool suspended);

bool proc_is_sandboxed();
bool proc_is_containerized();

bool is_app_coalition(); // (inherit)

void unsandbox(const char* sbtoken);

const char* generate_sandbox_extensions(bool ext);

const char* roothide_get_sandbox_profile(pid_t pid, char buffer[255]);

void killAllForBundle(const char* bundlePath);
void killAllForExecutable(const char* path);

bool isRemovableBundlePath(const char* path);
bool isSubPathOf(const char* parent, const char* child);

bool string_has_prefix(const char *str, const char* prefix);
bool string_has_suffix(const char* str, const char* suffix);
void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop));

int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path));

bool hasTrollstoreMarker(const char* path);
bool hasTrollstoreLiteMarker(const char* path);

bool isBlacklistedApp(const char* identifier);
bool isBlacklistedPath(const char* path);

bool isBlacklistedToken(audit_token_t* token);
bool isBlacklistedPid(pid_t pid);

pid_t* allocBlacklistProcessId();
void commitBlacklistProcessId(pid_t* pidp);

void loadAppStoredIdentifiers();

bool is_safe_bundle_identifier(const char* identifier);
bool is_sensitive_app_identifier(const char* identifier);
bool is_apple_internal_identifier(const char* identifier);

bool machoGetInfo(const char* path, bool* isMachO, bool* isLibrary);

int roothide_config_set_blacklist_enable(bool enabled);

bool checkpatchedexe(const char* executable_path);

#ifdef __OBJC__

void hook_class_method(Class clazz, SEL selector, void* replacement, void** old_ptr);
void hook_instance_method(Class clazz, SEL selector, void* replacement, void** old_ptr);

NSDictionary* proc_get_entitlements(pid_t pid);

#define APPLE_INTERNAL_IDENTIFIERS @[\
    @"com.apple.atrun",\
    @"com.apple.kdumpd",\
    @"com.apple.Terminal",\
]

//these apps may be signed with a (fake) certificate
#define SENSITIVE_APP_IDENTIFIERS @[\
    @"com.icraze.gtatracker",\
    @"com.Alfie.TrollInstallerX",\
    @"com.opa334.Dopamine",\
    @"com.opa334.Dopamine.roothide",\
    @"com.opa334.Dopamine-roothide",\
]

#endif
