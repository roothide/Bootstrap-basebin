#include <paths.h>
#include <unistd.h>
#include <sandbox.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <sys/proc_info.h>
#include "common.h"
#include "ipc.h"
#include "libbsd.h"
#include "envbuf.h"
#include "codesign.h"
#include "libproc.h"

void (*CommLogFunction)(const char* format, ...) = NULL;
void (*CommErrFunction)(const char* format, ...) = NULL;
void enableCommLog(void* debugLog, void* errorLog)
{
    CommLogFunction = debugLog;
    CommErrFunction = errorLog;
}

pid_t get_real_ppid()
{
    int32_t opt[4] = {
        CTL_KERN,
        KERN_PROC,
        KERN_PROC_PID,
        getpid(),
    };
    struct kinfo_proc info={0};
    size_t len = sizeof(struct kinfo_proc);
    if(sysctl(opt, 4, &info, &len, NULL, 0) == 0) {
        if((info.kp_proc.p_flag & P_TRACED) != 0) {
            return info.kp_proc.p_oppid;
        }
    }

    struct proc_bsdinfo procInfo;
    //some process may be killed by sandbox if call systme getppid() so try this first
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) == sizeof(procInfo)) {
        return procInfo.pbi_ppid;
    }

    return getppid();
}

pid_t proc_get_ppid(pid_t pid)
{
    struct proc_bsdinfo procInfo;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) != sizeof(procInfo)) {
        return -1;
    }
    return procInfo.pbi_ppid;
}

// #define PROC_PIDPATHINFO_MAXSIZE        (4*MAXPATHLEN)
char* proc_get_path(pid_t pid, char buffer[PATH_MAX])
{
    static char __thread threadbuffer[PATH_MAX];
    if(!buffer) buffer = threadbuffer;
    int ret = proc_pidpath(pid, buffer, PATH_MAX); /* proc_pidpath is not always reliable, 
    it will return ENOENT if the original executable file of a running process is removed from disk (e.g.  upgrading/reinstalling a package) */
    if (ret <= 0) return NULL;
    return buffer;
}

struct proc_uniqidentifierinfo {
	uint8_t                 p_uuid[16];             /* UUID of the main executable */
	uint64_t                p_uniqueid;             /* 64 bit unique identifier for process */
	uint64_t                p_puniqueid;            /* unique identifier for process's parent */
	int32_t                 p_idversion;            /* pid version */
	uint32_t                p_reserve2;             /* reserved for future use */
	uint64_t                p_reserve3;             /* reserved for future use */
	uint64_t                p_reserve4;             /* reserved for future use */
};
#define PROC_PIDUNIQIDENTIFIERINFO      17
#define PROC_PIDUNIQIDENTIFIERINFO_SIZE (sizeof(struct proc_uniqidentifierinfo))
int proc_get_pidversion(pid_t pid)
{
	struct proc_uniqidentifierinfo uniqidinfo = {0};
	int ret = proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo));
	if (ret <= 0) {
        return 0;
	}
	return uniqidinfo.p_idversion;
}

char* proc_get_identifier(pid_t pid, char buffer[255])
{
    static char __thread threadbuffer[255];
    if(!buffer) buffer = threadbuffer;
    
    struct csheader {
        uint32_t magic;
        uint32_t length;
    } header = {0};
    
    int result = csops(pid, CS_OPS_IDENTITY, &header, sizeof(header));
    if (result != 0 && errno != ERANGE) {
        return NULL;
    }
    
    uint32_t bufferLen = ntohl(header.length);

    char* csbuffer = malloc(bufferLen);
    if (!csbuffer) {
        return NULL;
    }
    
    result = csops(pid, CS_OPS_IDENTITY, csbuffer, bufferLen);
    if (result == 0) {
        char* identity = csbuffer + sizeof(struct csheader);
        strlcpy(buffer, identity, 255);
    }
    
    free(csbuffer);

    return buffer;
}

int proc_get_status(int pid) 
{
    struct proc_bsdinfo procInfo = {0};
    assert(proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) == sizeof(procInfo));
    return procInfo.pbi_status;
}

int proc_paused(pid_t pid, bool* paused)
{
	*paused = false;

	struct proc_bsdinfo procInfo={0};
	int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
	if(ret != sizeof(procInfo)) {
		SYSERR("bsdinfo failed, %d,%s\n", errno, strerror(errno));
		return -1;
	}

	if(procInfo.pbi_status == SSTOP)
	{
		SYSLOG("%d pstat=%x flag=%x xstat=%x\n", ret, procInfo.pbi_status, procInfo.pbi_flags, procInfo.pbi_xstatus);
		*paused = true;
	}
	else if(procInfo.pbi_status != SRUN) {
		SYSERR("unexpected %d pstat=%x\n", ret, procInfo.pbi_status);
		return -1;
	}

	return 0;
}

bool proc_traced(pid_t pid)
{
	int32_t opt[4] = {
		CTL_KERN,
		KERN_PROC,
		KERN_PROC_PID,
		pid,
	};
	struct kinfo_proc info={0};
	size_t len = sizeof(struct kinfo_proc);
	if(sysctl(opt, 4, &info, &len, NULL, 0) == 0) {
		if((info.kp_proc.p_flag & P_TRACED) != 0) {
			return true;
		}
	}
	
	struct proc_bsdinfo procInfo={0};
	if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) == sizeof(procInfo)) {
		if((procInfo.pbi_flags & PROC_FLAG_TRACED) != 0) {
			return true;
		}
	}

	return false;
}

// (inherit)
bool is_app_coalition()
{
    struct proc_bsdinfo procInfo;
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo))==sizeof(procInfo)) {
        if(procInfo.pbi_flags & PROC_FLAG_APPLICATION) {
            return true;
        }
    }
    return false;
}

void killAllForBundle(const char* bundlePath)
{
    SYSLOG("killAllForBundle: %s", bundlePath);
    
    char realBundlePath[PATH_MAX+1];
    if(!realpath(bundlePath, realBundlePath))
        return;
    
    size_t realBundlePathLen = strlen(realBundlePath);
    if(realBundlePath[realBundlePathLen] != '/') {
        strcat(realBundlePath, "/");
        realBundlePathLen++;
    }

    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    struct kinfo_proc *info;
    size_t length;
    size_t count;
    
    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
        return;
    if (!(info = malloc(length)))
        return;
    if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
        free(info);
        return;
    }
    count = length / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid == 0) {
            continue;
        }
        
        char executablePath[PATH_MAX];
        if(proc_pidpath(pid, executablePath, sizeof(executablePath)) > 0) {
            char realExecutablePath[PATH_MAX];
            if (realpath(executablePath, realExecutablePath)
                && strncmp(realExecutablePath, realBundlePath, realBundlePathLen) == 0) {
                int ret = kill(pid, SIGKILL);
                SYSLOG("killAllForBundle %s -> %d", realExecutablePath, ret);
            }
        }
    }
    free(info);
}

void killAllForExecutable(const char* path)
{
    SYSLOG("killallForExecutable %s, %d", path);
    
    struct stat st;
    if(stat(path, &st) < 0) return;

    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    struct kinfo_proc *info;
    size_t length;
    size_t count;
    
    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
        return;
    if (!(info = malloc(length)))
        return;
    if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
        free(info);
        return;
    }
    count = length / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid == 0) {
            continue;
        }
        
        char procpath[PATH_MAX];
        if(proc_pidpath(pid, procpath, sizeof(procpath)) > 0) {
            struct stat st2;
            if(stat(procpath, &st2) == 0) {
                if(st.st_ino==st2.st_ino && st.st_dev==st2.st_dev) {
                    int ret = kill(pid, SIGKILL);
                    //SYSLOG("killAllForExecutable(%d) %s -> %d", signal, path, ret);
                }
            }
        }
    }
    free(info);
}

int spawn(const char* path, char*const* argv, char*const* envp, void(^pid_out)(pid_t), void(^std_out)(char*,int), void(^err_out)(char*,int))
{
    SYSLOG("spawn %s", path);
    
    __block pid_t pid=0;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);

    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);

    int outPipe[2];
    pipe(outPipe);
    posix_spawn_file_actions_addclose(&action, outPipe[0]);
    posix_spawn_file_actions_adddup2(&action, outPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&action, outPipe[1]);
    
    int errPipe[2];
    pipe(errPipe);
    posix_spawn_file_actions_addclose(&action, errPipe[0]);
    posix_spawn_file_actions_adddup2(&action, errPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&action, errPipe[1]);

    
    dispatch_semaphore_t lock = dispatch_semaphore_create(0);
    
    dispatch_queue_t queue = dispatch_queue_create("spawnPipeQueue", DISPATCH_QUEUE_CONCURRENT);
    
    dispatch_source_t stdOutSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, outPipe[0], 0, queue);
    dispatch_source_t stdErrSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, errPipe[0], 0, queue);
    
    int outFD = outPipe[0];
    int errFD = errPipe[0];
    
    dispatch_source_set_cancel_handler(stdOutSource, ^{
        close(outFD);
        dispatch_semaphore_signal(lock);
        SYSLOG("stdout canceled [%d]", pid);
    });
    dispatch_source_set_cancel_handler(stdErrSource, ^{
        close(errFD);
        dispatch_semaphore_signal(lock);
        SYSLOG("stderr canceled [%d]", pid);
    });
    
    dispatch_source_set_event_handler(stdOutSource, ^{
        char buffer[BUFSIZ]={0};
        ssize_t bytes = read(outFD, buffer, sizeof(buffer)-1);
        if (bytes <= 0) {
            dispatch_source_cancel(stdOutSource);
            return;
        }
        SYSLOG("spawn[%d] stdout: %s", pid, buffer);
        if(std_out) std_out(buffer,bytes);
    });
    dispatch_source_set_event_handler(stdErrSource, ^{
        char buffer[BUFSIZ]={0};
        ssize_t bytes = read(errFD, buffer, sizeof(buffer)-1);
        if (bytes <= 0) {
            dispatch_source_cancel(stdErrSource);
            return;
        }
        SYSLOG("spawn[%d] stderr: %s", pid, buffer);
        if(err_out) err_out(buffer,bytes);
    });
    
    dispatch_resume(stdOutSource);
    dispatch_resume(stdErrSource);
    
    int spawnError = posix_spawn(&pid, path, &action, &attr, argv, envp);
    SYSLOG("spawn ret=%d, pid=%d", spawnError, pid);
    
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&action);
    
    close(outPipe[1]);
    close(errPipe[1]);
    
    if(spawnError != 0)
    {
        SYSERR("posix_spawn error %d:%s\n", spawnError, strerror(spawnError));
        dispatch_source_cancel(stdOutSource);
        dispatch_source_cancel(stdErrSource);
        return spawnError;
    }

    if(pid_out) pid_out(pid);
    
    //wait stdout
    dispatch_semaphore_wait(lock, DISPATCH_TIME_FOREVER);
    //wait stderr
    dispatch_semaphore_wait(lock, DISPATCH_TIME_FOREVER);
    
    int status=0;
    while(waitpid(pid, &status, 0) != -1)
    {
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        } else if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        //keep waiting?return status;
    };
    return -1;
}

int spawnBootstrap(char*const* argv, __strong NSString** stdOut, __strong NSString** stdErr)
{
    NSMutableArray* argArr = [[NSMutableArray alloc] init];
    for(int i=1; argv[i]; i++) [argArr addObject:[NSString stringWithUTF8String:argv[i]]];
    SYSLOG("spawnBootstrap %s with %s", argv[0], argArr.debugDescription.UTF8String);
    
    char **envc = envbuf_mutcopy(environ);
    
    envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", jbroot(@"/basebin/bootstrap.dylib").fileSystemRepresentation, 1);
    
    
    __block NSMutableString* outString=nil;
    __block NSMutableString* errString=nil;
    
    if(stdOut) outString = [NSMutableString new];
    if(stdErr) errString = [NSMutableString new];
    
    
    int retval = spawn(jbroot(@(argv[0])).fileSystemRepresentation, argv, envc, nil, ^(char* outstr, int length){
        NSString *str = [[NSString alloc] initWithBytes:outstr length:length encoding:NSASCIIStringEncoding];
        if(stdOut) [outString appendString:str];
    }, ^(char* errstr, int length){
        NSString *str = [[NSString alloc] initWithBytes:errstr length:length encoding:NSASCIIStringEncoding];
        if(stdErr) [errString appendString:str];
    });
    
    if(stdOut) *stdOut = outString.copy;
    if(stdErr) *stdErr = errString.copy;
    
    envbuf_free(envc);
    
    return retval;
}

int spawnRoot(NSString* path, NSArray* args, __strong NSString** stdOut, __strong NSString** stdErr)
{
    SYSLOG("spawnRoot %s with %s", path.fileSystemRepresentation, args.debugDescription.UTF8String);
    
    NSMutableArray* argsM = args.mutableCopy ?: [NSMutableArray new];
    [argsM insertObject:path atIndex:0];
    
    NSUInteger argCount = [argsM count];
    char **argsC = (char **)malloc((argCount + 1) * sizeof(char*));

    for (NSUInteger i = 0; i < argCount; i++)
    {
        argsC[i] = strdup([[argsM objectAtIndex:i] UTF8String]);
    }
    argsC[argCount] = NULL;

    
    __block NSMutableString* outString=nil;
    __block NSMutableString* errString=nil;
    
    if(stdOut) outString = [NSMutableString new];
    if(stdErr) errString = [NSMutableString new];
    
    int retval = spawn(path.fileSystemRepresentation, argsC, environ, nil, ^(char* outstr, int length){
        NSString *str = [[NSString alloc] initWithBytes:outstr length:length encoding:NSASCIIStringEncoding];
        if(stdOut) [outString appendString:str];
    }, ^(char* errstr, int length){
        NSString *str = [[NSString alloc] initWithBytes:errstr length:length encoding:NSASCIIStringEncoding];
        if(stdErr) [errString appendString:str];
    });
    
    if(stdOut) *stdOut = outString.copy;
    if(stdErr) *stdErr = errString.copy;
    
    for (NSUInteger i = 0; i < argCount; i++)
    {
        free(argsC[i]);
    }
    free(argsC);
    
    return retval;
}

bool checkpatchedexe()
{
	char executablePath[PATH_MAX]={0};
	uint32_t bufsize=sizeof(executablePath);
	assert(_NSGetExecutablePath(executablePath, &bufsize) == 0);
	
	char patcher[PATH_MAX];
	snprintf(patcher, sizeof(patcher), "%s.roothidepatch", executablePath);
	if(access(patcher, F_OK)==0) 
		return false;

	return true;
}

/* pbi_flags values */
#define PROC_FLAG_TRACED        2       /* process currently being traced, possibly by gdb */
int requireJIT()
{
	static int result = -1;
	
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		int32_t opt[4] = {
			CTL_KERN,
			KERN_PROC,
			KERN_PROC_PID,
			getpid(),
		};
		struct kinfo_proc info={0};
		size_t len = sizeof(struct kinfo_proc);
		if(sysctl(opt, 4, &info, &len, NULL, 0) == 0) {
			if((info.kp_proc.p_flag & P_TRACED) != 0) {
				result = 0;
				return;
			}
		}
		
		struct proc_bsdinfo procInfo={0};
		if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) == sizeof(procInfo)) {
			if((procInfo.pbi_flags & PROC_FLAG_TRACED) != 0) {
				result = 0;
				return;
			}
		}
		
		result = bsd_enableJIT();
	});
	return result;
}

bool string_has_prefix(const char *str, const char *prefix)
{
    if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char *str, const char *suffix)
{
    if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop))
{
	char *stringCopy = strdup(string);
	char *curString = strtok(stringCopy, separator);
	while (curString != NULL) {
		bool stop = false;
		enumBlock(curString, &stop);
		if (stop) break;
		curString = strtok(NULL, separator);
	}
	free(stringCopy);
}

// Derived from posix_spawnp in Apple libc
int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path))
{
	const char *env_path;
	char *bp;
	char *cur;
	char *p;
	char **memp;
	int lp;
	int ln;
	int cnt;
	int err = 0;
	int eacces = 0;
	struct stat sb;
	char path_buf[PATH_MAX];

	env_path = searchPath;
	if (!env_path) {
		env_path = getenv("PATH");
		if (!env_path) {
			env_path = _PATH_DEFPATH;
		}
	}

	/* If it's an absolute or relative path name, it's easy. */
	if (index(file, '/')) {
		bp = (char *)file;
		cur = NULL;
		goto retry;
	}
	bp = path_buf;

	/* If it's an empty path name, fail in the usual POSIX way. */
	if (*file == '\0')
		return (ENOENT);

	if ((cur = alloca(strlen(env_path) + 1)) == NULL)
		return ENOMEM;
	strcpy(cur, env_path);
	while ((p = strsep(&cur, ":")) != NULL) {
		/*
		 * It's a SHELL path -- double, leading and trailing colons
		 * mean the current directory.
		 */
		if (*p == '\0') {
			p = ".";
			lp = 1;
		} else {
			lp = strlen(p);
		}
		ln = strlen(file);

		/*
		 * If the path is too long complain.  This is a possible
		 * security issue; given a way to make the path too long
		 * the user may spawn the wrong program.
		 */
		if (lp + ln + 2 > sizeof(path_buf)) {
			err = ENAMETOOLONG;
			goto done;
		}
		bcopy(p, path_buf, lp);
		path_buf[lp] = '/';
		bcopy(file, path_buf + lp + 1, ln);
		path_buf[lp + ln + 1] = '\0';

retry:		err = attemptHandler(bp);
		switch (err) {
		case E2BIG:
		case ENOMEM:
		case ETXTBSY:
			goto done;
		case ELOOP:
		case ENAMETOOLONG:
		case ENOENT:
		case ENOTDIR:
			break;
		case ENOEXEC:
			goto done;
		default:
			/*
			 * EACCES may be for an inaccessible directory or
			 * a non-executable file.  Call stat() to decide
			 * which.  This also handles ambiguities for EFAULT
			 * and EIO, and undocumented errors like ESTALE.
			 * We hope that the race for a stat() is unimportant.
			 */
			if (stat(bp, &sb) != 0)
				break;
			if (err == EACCES) {
				eacces = 1;
				continue;
			}
			goto done;
		}
	}
	if (eacces)
		err = EACCES;
	else
		err = ENOENT;
done:
	return (err);
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
char* getAppUUIDPath(const char* path)
{
    if(!path) return NULL;

    char abspath[PATH_MAX];
    if(!realpath(path, abspath)) return NULL;

    if(strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NULL;

    char* p1 = abspath + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NULL;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NULL;
	
	*p2 = '\0';

	return strdup(abspath);
}

bool isRemovableBundlePath(const char* path)
{
    const char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;
	free((void*)uuidpath);
	return true;
}

bool hasTrollstoreMarker(const char* path)
{
    char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;

	char* markerpath=NULL;
	asprintf(&markerpath, "%s/_TrollStore", uuidpath);

	int ret = access(markerpath, F_OK);
    if(ret != 0) {
        free((void*)markerpath); markerpath = NULL;
        asprintf(&markerpath, "%s/_TrollStoreLite", uuidpath);
        ret = access(markerpath, F_OK);
    }

    free((void*)markerpath);
	free((void*)uuidpath);

	return ret==0;
}

bool hasTrollstoreLiteMarker(const char* path)
{
    char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;

	char* markerpath=NULL;
	asprintf(&markerpath, "%s/_TrollStoreLite", uuidpath);

	int ret = access(markerpath, F_OK);

    free((void*)markerpath);
	free((void*)uuidpath);

	return ret==0;
}

bool isSubPathOf(const char* child, const char* parent)
{
	char real_child[PATH_MAX]={0};
	char real_parent[PATH_MAX]={0};

	if(!realpath(child, real_child)) return false;
	if(!realpath(parent, real_parent)) return false;

	if(!string_has_prefix(real_child, real_parent))
		return false;

	return real_child[strlen(real_parent)] == '/';
}


NSMutableArray<NSString*>* StoredAppIdentifiers = nil;

void loadAppStoredIdentifiers()
{
    StoredAppIdentifiers = [[NSMutableArray alloc] init];

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *applicationsPath = @"/private/var/containers/Bundle/Application/";
    
    NSError *error = nil;
    NSArray *appContainers = [fileManager contentsOfDirectoryAtPath:applicationsPath error:&error];
    if (error) {
        SYSERR("Error reading Application directory: %s", error.description.UTF8String);
        abort();
    }
    
    for (NSString *containerUUID in appContainers) 
    {
        NSString *containerPath = [applicationsPath stringByAppendingPathComponent:containerUUID];

        NSString *metadataPlistPath = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *metadataPlist = [NSDictionary dictionaryWithContentsOfFile:metadataPlistPath];
        NSString *MCMMetadataIdentifier = metadataPlist[@"MCMMetadataIdentifier"];
        if(!MCMMetadataIdentifier) {
            SYSLOG("Skipping container with no MCMMetadataIdentifier: %s", containerPath.UTF8String);
            continue;
        }

        if([fileManager fileExistsAtPath:[containerPath stringByAppendingPathComponent:@"_TrollStore"]]
            || [fileManager fileExistsAtPath:[containerPath stringByAppendingPathComponent:@"_TrollStoreLite"]])
        {
            SYSLOG("Skipping trollstored app container: %s : %s", MCMMetadataIdentifier.UTF8String, containerPath.UTF8String);
            continue;
        }

        if(![fileManager fileExistsAtPath:[containerPath stringByAppendingPathComponent:@"iTunesMetadata.plist"]])
        {
            SYSLOG("Skipping non-stored app container: %s : %s", MCMMetadataIdentifier.UTF8String, containerPath.UTF8String);
            continue;
        }

        NSArray *containerContents = [fileManager contentsOfDirectoryAtPath:containerPath error:nil];
        for (NSString *item in containerContents)
        {
            if ([item hasSuffix:@".app"]) 
            {
                NSString *appPath = [containerPath stringByAppendingPathComponent:item];
                NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                NSString *appBundleID = infoPlist[@"CFBundleIdentifier"];

                if([appBundleID isEqualToString:MCMMetadataIdentifier]==NO) {
                    SYSLOG("*** Mismatched Bundle ID and MCMMetadataIdentifier: %s != %s : %s", appBundleID.UTF8String, MCMMetadataIdentifier.UTF8String, appPath.UTF8String);
                }
                
                if(![fileManager fileExistsAtPath:[appPath stringByAppendingPathComponent:@"SC_Info"]])
                {
                    SYSLOG("Skipping non-encrypted app: %s", appPath.UTF8String);
                    continue;
                }

                if (appBundleID) {
                    SYSLOG("App: %s -> %s", item.UTF8String, appBundleID.UTF8String);
                    [StoredAppIdentifiers addObject:appBundleID];
                } else {
                    SYSLOG("*** No Bundle ID found: %s", appPath.UTF8String);
                    continue;
                }
                
                NSString *plugInsPath = [appPath stringByAppendingPathComponent:@"PlugIns"];
                if ([fileManager fileExistsAtPath:plugInsPath]) 
                {
                    NSArray *plugIns = [fileManager contentsOfDirectoryAtPath:plugInsPath error:nil];
                    for (NSString *plugIn in plugIns) 
                    {
                        NSString *plugInPath = [plugInsPath stringByAppendingPathComponent:plugIn];
                        NSString *plugInInfoPath = [plugInPath stringByAppendingPathComponent:@"Info.plist"];
                        NSDictionary *plugInInfo = [NSDictionary dictionaryWithContentsOfFile:plugInInfoPath];
                        NSString *plugInBundleID = plugInInfo[@"CFBundleIdentifier"];
                        
                        if (plugInBundleID) {
                            SYSLOG("  PlugIn: %s -> %s", plugIn.UTF8String, plugInBundleID.UTF8String);
                            [StoredAppIdentifiers addObject:plugInBundleID];
                        } else {
                            SYSLOG("  *** No Bundle ID found: %s", plugInPath.UTF8String);
                        }
                    }
                }
            }
        }
    }
}

bool is_apple_internal_identifier(const char* identifier)
{
    if(!identifier || !*identifier) return false;
    
    for(NSString* item in APPLE_INTERNAL_IDENTIFIERS) {
        if([@(identifier) hasPrefix:item]) {
            return true;
        }
    }
    return false;
}

bool is_sensitive_app_identifier(const char* identifier)
{
    if(!identifier || !*identifier) return false;

    for(NSString* item in SENSITIVE_APP_IDENTIFIERS) {
        if([@(identifier) hasPrefix:item]) {
            return true;
        }
    }
    return false;
}

bool is_safe_bundle_identifier(const char* identifier)
{
    if(!identifier || !*identifier) return false;

    /* ios15 /System/Library/LaunchDaemons/com.apple.tvremoted.plist */
    if(strcmp(identifier, "$(PRODUCT_BUNDLE_IDENTIFIER)")==0) {
        return true;
    }

    if(string_has_prefix(identifier, "lockdown.") && strstr(identifier, ".com.apple.")) {
        return true;
    }

    if(string_has_prefix(identifier, "com.apple."))
    {
        if(is_apple_internal_identifier(identifier)) {
            return false;
        } else {
            return true;
        }
    }

    if(is_sensitive_app_identifier(identifier)) {
        return false;
    }

    assert(StoredAppIdentifiers != nil);
    if([StoredAppIdentifiers containsObject:@(identifier)]) {
        return true;
    }

    return false;
}

void machoEnumerateArchs(FILE* machoFile, bool (^archEnumBlock)(struct mach_header_64* header, uint32_t offset))
{
	struct mach_header_64 mh={0};
	if(fseek(machoFile,0,SEEK_SET)!=0)return;
	if(fread(&mh,sizeof(mh),1,machoFile)!=1)return;
	
	if(mh.magic==FAT_MAGIC || mh.magic==FAT_CIGAM)//and || mh.magic==FAT_MAGIC_64 || mh.magic==FAT_CIGAM_64? with fat_arch_64
	{
		struct fat_header fh={0};
		if(fseek(machoFile,0,SEEK_SET)!=0)return;
		if(fread(&fh,sizeof(fh),1,machoFile)!=1)return;
		
		for(int i = 0; i < OSSwapBigToHostInt32(fh.nfat_arch); i++)
		{
			uint32_t archMetadataOffset = sizeof(fh) + sizeof(struct fat_arch) * i;

			struct fat_arch fatArch={0};
			if(fseek(machoFile, archMetadataOffset, SEEK_SET)!=0)break;
			if(fread(&fatArch, sizeof(fatArch), 1, machoFile)!=1)break;

			if(fseek(machoFile, OSSwapBigToHostInt32(fatArch.offset), SEEK_SET)!=0)break;
			if(fread(&mh, sizeof(mh), 1, machoFile)!=1)break;

			if(mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64) continue; //require Macho64
			
			if(!archEnumBlock(&mh, OSSwapBigToHostInt32(fatArch.offset))) 
				break;
		}
	}
	else if(mh.magic == MH_MAGIC_64 || mh.magic == MH_CIGAM_64) //require Macho64
	{
		archEnumBlock(&mh, 0);
	}
}

bool machoGetInfo(const char* path, bool *isMachoOut, bool *isLibraryOut)
{
    FILE* fp = fopen(path, "rb");
    if(!fp) return false;

	__block bool isMacho=false;
	__block bool isLibrary = false;
	
	machoEnumerateArchs(fp, ^bool(struct mach_header_64* header, uint32_t offset) {
		switch(OSSwapLittleToHostInt32(header->filetype)) {
			case MH_DYLIB:
			case MH_BUNDLE:
				isLibrary = true;
			case MH_EXECUTE:
				isMacho = true;
				return false;

			default:
				return true;
		}
	});

	if (isMachoOut) *isMachoOut = isMacho;
	if (isLibraryOut) *isLibraryOut = isLibrary;

    fclose(fp);
    return true;
}

void unsandbox(const char* sbtoken)
{
	char extensionsCopy[strlen(sbtoken)];
	strcpy(extensionsCopy, sbtoken);
	char *extensionToken = strtok(extensionsCopy, "|");
	while (extensionToken != NULL) {
		sandbox_extension_consume(extensionToken);
		extensionToken = strtok(NULL, "|");
	}
}

const char* roothide_get_sandbox_profile(pid_t pid, char buffer[255])
{
    static char __thread threadbuffer[255];
    if(!buffer) buffer = threadbuffer;
    
    struct csheader {
        uint32_t magic;
        uint32_t length;
    } header = {0};
    
    int result = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, &header, sizeof(header));
    if (result != 0 && errno != ERANGE) {
        return NULL;
    }
    
    uint32_t bufferLen = ntohl(header.length);

    typedef struct __SC_GenericBlob {
        uint32_t magic;
        uint32_t length;
        char data[];
    } CS_GenericBlob __attribute__ ((aligned(1)));

    char* csbuffer = malloc(bufferLen);
    if (!csbuffer) {
        return NULL;
    }
    
    result = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, csbuffer, bufferLen);
    if (result == 0) {
        char* entitlements = csbuffer + sizeof(CS_GenericBlob);
        NSData* data = [NSData dataWithBytes:entitlements length:(bufferLen - sizeof(CS_GenericBlob))];
        NSDictionary* plist = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
        
        NSString* profile = nil;

        NSArray* profiles = plist[@"roothide-seatbelt-profiles"];
        if(profiles.count > 0) {
            profile = profiles[0];
        }
        if(!profile) {
            profile = plist[@"roothide-com.apple.private.sandbox.profile:embedded"];
        }
        if(!profile) {
            profile = plist[@"roothide-com.apple.private.sandbox.profile"];
        }

        if(profile) {
            strlcpy(buffer, profile.UTF8String, 255);
        } else {
            buffer = NULL;
        }
    }

    free(csbuffer);
    csbuffer = NULL;

    return buffer;
}

const char* generate_sandbox_extensions(bool ext)
{
    NSMutableString *extensionString = [NSMutableString new];

    char service_name[256]={0};
    snprintf(service_name, sizeof(service_name), "com.roothide.bootstrapd-%016llX", jbrand());

    char jbrootbase[PATH_MAX];
    char jbrootsecondary[PATH_MAX];
    snprintf(jbrootbase, sizeof(jbrootbase), "/private/var/containers/Bundle/Application/.jbroot-%016llX/", jbrand());
    snprintf(jbrootsecondary, sizeof(jbrootsecondary), "/private/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX/", jbrand());

    [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.app-sandbox.read", jbrootbase, 0)]];
    [extensionString appendString:@"|"];
    [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.sandbox.executable", jbrootbase, 0)]];
    [extensionString appendString:@"|"];

    char* class = ext ? "com.apple.app-sandbox.read-write" : "com.apple.app-sandbox.read";
    [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file(class, jbrootsecondary, 0)]];
    [extensionString appendString:@"|"];
    [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.sandbox.executable", jbrootsecondary, 0)]];
    [extensionString appendString:@"|"];
    [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_mach("com.apple.app-sandbox.mach", service_name, 0, 0)]];
    [extensionString appendString:@"|"];
    [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_mach("com.apple.security.exception.mach-lookup.global-name", service_name, 0, 0)]];

    return strdup(extensionString.UTF8String);
}
