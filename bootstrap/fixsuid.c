#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <spawn.h>
#include <signal.h>
#include <assert.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/syslimits.h>

#include "common.h"

enum {
	PERSONA_INVALID      = 0,
	PERSONA_GUEST        = 1,
	PERSONA_MANAGED      = 2,
	PERSONA_PRIV         = 3,
	PERSONA_SYSTEM       = 4,
	PERSONA_DEFAULT      = 5,
	PERSONA_SYSTEM_PROXY = 6,
	PERSONA_SYS_EXT      = 7,
	PERSONA_ENTERPRISE   = 8,

	PERSONA_TYPE_MAX     = PERSONA_ENTERPRISE,
};

#define PERSONA_INFO_V1       1
#define PERSONA_INFO_V2       2

struct kpersona_info {
	/* v1 fields */
	uint32_t persona_info_version;

	uid_t    persona_id;
	int      persona_type;
	gid_t    persona_gid; /* unused */
	uint32_t persona_ngroups; /* unused */
	gid_t    persona_groups[NGROUPS]; /* unused */
	uid_t    persona_gmuid; /* unused */
	char     persona_name[MAXLOGNAME + 1];

	/* v2 fields */
	uid_t    persona_uid;
} __attribute__((packed));

extern int kpersona_find_by_type(int persona_type, uid_t *id, size_t *idlen);
extern int kpersona_getpath(uid_t id, char path[MAXPATHLEN]);
extern int kpersona_pidinfo(pid_t id, struct kpersona_info *info);
extern int kpersona_info(uid_t id, struct kpersona_info *info);
extern int kpersona_find(const char *name, uid_t uid, uid_t *id, size_t *idlen);
extern int kpersona_alloc(struct kpersona_info *info, uid_t *id);


int available_persona_id()
{
    struct kpersona_info info={PERSONA_INFO_V1};
    assert(kpersona_pidinfo(getpid(), &info) == 0);

    int current_persona_id = info.persona_id;

    for(int t=1; t<=PERSONA_TYPE_MAX; t++)
    {
        uid_t personas[128]={0};
        size_t npersonas = 128;

        if(kpersona_find_by_type(t, personas, &npersonas) <= 0)
            continue;

        for(int i=0; i<npersonas; i++)
        {
            if(personas[i] != current_persona_id)
                return personas[i];
        }
    }
    return 0;
}


#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* attr, uid_t persona_id, uint32_t flags);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

extern char** NXArgv; // __NSGetArgv() not working on ctor
extern int    NXArgc;

#include <sys/stat.h>

void fixsuid()
{
    if(getenv("UIDFIX")) {
        uid_t uid = atoi(getenv("UIDFIX"));
        setreuid(uid, geteuid());
        unsetenv("UIDFIX");
    }
    if(getenv("GIDFIX")) {
        uid_t gid = atoi(getenv("GIDFIX"));
        setregid(gid, getegid());
        unsetenv("GIDFIX");
    }

    char path[PATH_MAX]={0};
    uint32_t bufsize=sizeof(path);
    assert(_NSGetExecutablePath(path, &bufsize) == 0);

    struct stat st;
	assert(stat(path, &st) == 0);

    if (!S_ISREG(st.st_mode) || !(st.st_mode & (S_ISUID | S_ISGID)))
        return;

    if( ((st.st_mode&S_ISUID)==0 || st.st_uid==geteuid())
     && ((st.st_mode&S_ISGID)==0 || st.st_gid==getegid()) )
        return;

    
    char uidbuf[32], gidbuf[32];
    snprintf(uidbuf, sizeof(uidbuf), "%d", geteuid());
    snprintf(gidbuf, sizeof(gidbuf), "%d", getegid());
    setenv("UIDFIX", uidbuf, 1);
    setenv("GIDFIX", gidbuf, 1);

    posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);

    int persona_id = available_persona_id();
    assert(persona_id != 0);

    posix_spawnattr_set_persona_np(&attr, persona_id, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
	if(st.st_mode & S_ISUID) posix_spawnattr_set_persona_uid_np(&attr, st.st_uid);
	if(st.st_mode & S_ISGID) posix_spawnattr_set_persona_gid_np(&attr, st.st_gid);

	posix_spawn_file_actions_t action;
	posix_spawn_file_actions_init(&action);

	pid_t pid=0;
	int ret = posix_spawn_hook(&pid, path, &action, &attr, NXArgv, environ);

    assert(ret==0 && pid>0);

    int status=0;
    while(waitpid(pid, &status, 0) != -1)
    {
        if (WIFSIGNALED(status)) {
            kill(getpid(), -WTERMSIG(status));
        } else if (WIFEXITED(status)) {
            exit(WEXITSTATUS(status));
        }
        //keep waiting?return status;
    };
    
    exit(-1);
}

void runAsRoot()
{
    if(getuid()==0)
        return;

    char path[PATH_MAX]={0};
    uint32_t bufsize=sizeof(path);
    assert(_NSGetExecutablePath(path, &bufsize) == 0);

    posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);

    int persona_id = available_persona_id();
    assert(persona_id != 0);

    posix_spawnattr_set_persona_np(&attr, persona_id, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
	posix_spawnattr_set_persona_uid_np(&attr, 0);
	posix_spawnattr_set_persona_gid_np(&attr, 0);

	posix_spawn_file_actions_t action;
	posix_spawn_file_actions_init(&action);

	pid_t pid=0;
	int ret = posix_spawn_hook(&pid, path, &action, &attr, NXArgv, environ);

    assert(ret==0 && pid>0);

    int status=0;
    while(waitpid(pid, &status, 0) != -1)
    {
        if (WIFSIGNALED(status)) {
            kill(getpid(), -WTERMSIG(status));
        } else if (WIFEXITED(status)) {
            exit(WEXITSTATUS(status));
        }
        //keep waiting?return status;
    };
    
    exit(-1);
}

