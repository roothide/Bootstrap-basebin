#include <bootstrap.h>
#include <xpc/xpc.h>

#include "ipc.h"
#include "libbsd.h"
#include "common.h"

#undef	SYSLOG
#define	SYSLOG(...)

bool bsd_tick_mach_service()
{
	bool retval = true;
	
	char service_name[256]={0};
	snprintf(service_name, sizeof(service_name), "com.roothide.bootstrapd-%016llX", jbrand());

	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_look_up(bootstrap_port, service_name, &port);
	if(kr != KERN_SUCCESS || !MACH_PORT_VALID(port)) {
		SYSERR("bootstrap_check_in (%s) port=%x kr=%x,%s", service_name, port, kr, bootstrap_strerror(kr));
		return false;
	}

	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", 0);

	xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
	if(pipe)
	{
		xpc_object_t reply = NULL;
		int err = xpc_pipe_routine(pipe, message, &reply);
		if(err==0)
		{
			assert(reply != NULL);

			uint64_t ack = xpc_dictionary_get_uint64(reply, "ack");

			retval = (ack == 1);

			// xpc_release(reply);
		}
	}
	else
	{
		SYSERR("xpc_pipe_create_from_port failed");
		retval = false;
	}

	mach_port_deallocate(mach_task_self(), port);
	// xpc_release(message);
	// xpc_release(pipe);

	return retval;
}

int bsd_enableJIT()
{
    int result=-1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_ENABLE_JIT, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
        if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}

int bsd_enableJIT2(pid_t pid)
{
    int result=-1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_ENABLE_JIT2, @{@"pid":@(pid)});
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
        if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}

const char* bsd_getsbtoken()
{
	const char* result=NULL;

	int sd = connect_to_server();
	if(sd <= 0) return NULL;
	int req = request(sd, BSD_REQ_GET_SBTOKEN, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		result = strdup([rep[@"sbtoken"] UTF8String]);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
	}
	close(sd);

	return result;
}

int bsd_opensshctl(bool run)
{
	int result = -1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, run ? BSD_REQ_SSH_START : BSD_REQ_SSH_STOP, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}

int bsd_opensshcheck()
{
	int result = -1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_SSH_CHECK, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}

int bsd_stopServer()
{
	int result = -1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_STOP_SERVER, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}

int bsd_checkServer()
{
	int result = -1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_CHECK_SERVER, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}

int bsd_varClean()
{
	int result = -1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_VAR_CLEAN, @{@"bundleIdentifier":NSBundle.mainBundle.bundleIdentifier});
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}
