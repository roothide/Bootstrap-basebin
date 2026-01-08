#include <Foundation/Foundation.h>
#include <kern_memorystatus.h>
#include <mach-o/dyld.h>
#include <libproc.h>
#include <spawn.h>

#include "commlib.h"
#include "jbclient.h"
#include "jailbreakd.h"
#include "crashreporter.h"

void jailbreakd_received_message(mach_port_t port);

void setJetsamLimit(uint32_t sizeInMB, bool is_fatal_limit)
{
	uint32_t cmd = is_fatal_limit ? MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT : MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK;
	int rc = memorystatus_control(cmd, getpid(), sizeInMB, NULL, 0);
	if (rc < 0) { perror ("memorystatus_control"); exit(rc);}
}

int main(int argc, char* argv[])
{
	crashreporter_start();

	setJetsamLimit(50, false);

#ifdef ENABLE_LOGS
	enableCommLog(FileLogDebugFunction, FileLogErrorFunction);
#endif

	FileLogDebug("Hello from jailbrakd! uid=%d pid=%d ppid=%d", getuid(), getpid(), getppid());

	@autoreleasepool {

		mach_port_t *registeredPorts=NULL;
		mach_msg_type_number_t registeredPortsCount = 0;
		kern_return_t kr = mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount);
		if(kr != KERN_SUCCESS || registeredPortsCount < 3) {
			FileLogError("mach_ports_lookup error: %d, %x, %s", registeredPortsCount, kr, mach_error_string(kr));
			return 1;
		}
		for(int i=0; i<registeredPortsCount; i++) {
			FileLogDebug("registeredPorts[%d]: %x", i, registeredPorts[i]);
		}

		mach_port_t bootstraport = registeredPorts[2];
		if(!MACH_PORT_VALID(bootstraport)) {
			FileLogError("invalid bootstraport");
			return 2;
		}
		FileLogDebug("bootstraport: %x", bootstraport);

		registeredPorts[2] = MACH_PORT_NULL;
		mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);

		jbclient_xpc_set_custom_port(bootstraport);

		FileLogDebug("check in jailbreakd port...");
		mach_port_t serverPort = jbclient_jailbreakd_checkin();
		if (!MACH_PORT_VALID(serverPort)) {
			FileLogError("Failed to check in server port");
			return 6;
		}

		FileLogDebug("starting jailbreakd server, port=%x", serverPort);

		dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, dispatch_get_main_queue());
		dispatch_source_set_event_handler(source, ^{
			jailbreakd_received_message(serverPort);
		});
		dispatch_resume(source);

		dispatch_main();
	}

	FileLogDebug("jailbreakd exit...");
	return 0;
}
