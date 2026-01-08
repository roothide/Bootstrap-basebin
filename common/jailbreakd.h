#ifndef JAILBREAKD_H
#define JAILBREAKD_H

#include <unistd.h>
#include <xpc/xpc.h>

typedef enum {
	JBD_MSG_TEST_CALL = 101,
	JBD_MSG_SYSTEMWIDE_LOG = 102,
	JBD_MSG_SPAWN_PATCH_CHILD = 1001,
	JBD_MSG_SPAWN_EXEC_START = 1002,
	JBD_MSG_SPAWN_EXEC_CANCEL = 1003,
	JBD_MSG_EXEC_TRACE_START = 1004,
	JBD_MSG_EXEC_TRACE_CANCEL = 1005,
	JBD_MSG_PROCESS_ENABLE_JIT = 1006,
} JBD_MESSAGE_ID;

int initJailbreakd(int(*handler)(xpc_object_t));

void setJailbreakdProcess(pid_t pid);

mach_port_t jailbreakdClientPort();
mach_port_t jailbreakdServerPort();

int jbdTestCall(int value);
int jbdSystemwideLog(const char* fmt, ...);

int jbdProcessEnableJIT(int pid, bool resume);
int jbdSpawnPatchChild(int pid, bool resume);
int jbdSpawnExecStart(const char* execfile, bool resume);
int jbdSpawnExecCancel(const char* execfile);
int jbdExecTraceStart(const char* execfile, bool* traced);
int jbdExecTraceCancel(const char* execfile);

#endif // JAILBREAKD_H