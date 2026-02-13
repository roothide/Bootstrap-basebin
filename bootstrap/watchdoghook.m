#include <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include "crashreporter.h"
#include "common.h"
#include "dobby.h"

#include <roothide.h>

int reboot3(uint64_t flags, ...);
#define RB2_USERREBOOT (0x2000000000000000llu)

kern_return_t (*IOConnectCallStructMethod_orig)(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt) = NULL;
kern_return_t (*IOServiceOpen_orig)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect);
mach_port_t gIOWatchdogConnection = MACH_PORT_NULL;

kern_return_t IOServiceOpen_hook(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect)
{
	kern_return_t orig = IOServiceOpen_orig(service, owningTask, type, connect);
	if (orig == KERN_SUCCESS && connect) {
		if (IOObjectConformsTo(service, "IOWatchdog")) {
			// save mach port of IOWatchdog for check later
			gIOWatchdogConnection = *connect;
		}
	}
	return orig;
}

kern_return_t IOConnectCallStructMethod_hook(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt)
{
	if (connection == gIOWatchdogConnection) 
	{
		if (selector == 2) {

			const char *panicMessage = (const char *)inputStruct;

			FILE *outFile = crashreporter_open_outfile("userspace-panic", NULL);
			ASSERT(outFile != NULL);
			if (outFile) {
				fprintf(outFile, "\n%s", panicMessage);
				fprintf(outFile, "\n\nThis panic was prevented by Bootstrap and a userspace reboot was done instead.");
				crashreporter_save_outfile(outFile);
			}

			FILE* msgFile = fopen(jbroot("/var/mobile/.watchdogmsg"), "w");
			ASSERT(msgFile != NULL);
			fputs(panicMessage, msgFile);
			fclose(msgFile);

			if(access(jbroot("/var/mobile/.tweakenabled"), F_OK) == 0) {
				ASSERT(unlink(jbroot("/var/mobile/.tweakenabled")) == 0);
			}

			reboot3(RB2_USERREBOOT);

			return 0;
		}
	}
	return IOConnectCallStructMethod_orig(connection, selector, inputStruct, inputStructCnt, outputStruct, outputStructCnt);
}

int init_watchdoghook()
{
	SYSLOG("init watchdog hook...\n");

	if(requireJIT() != 0) {
		return -1;
	}

	DobbyHook(IOServiceOpen, (void *)&IOServiceOpen_hook, (void **)&IOServiceOpen_orig);
	DobbyHook(IOConnectCallStructMethod, (void *)&IOConnectCallStructMethod_hook, (void **)&IOConnectCallStructMethod_orig);

	return 0;
}
