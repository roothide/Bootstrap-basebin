#include "ipc.h"
#include "libbsd.h"
#include "common.h"

#undef	SYSLOG
#define	SYSLOG(...)

bool bsd_tick_mach_service()
{
	bool result = false;

	void* conn = mach_ipc_connect();
	if(!conn) return false;

	NSDictionary* rep=nil;
	int req = mach_ipc_request(conn, BSD_REQ_CHECK_SERVER, nil, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = (resultObj.intValue == 0);
	}

	mach_ipc_close(conn);

	return result;
}

int bsd_enableJIT(pid_t pid)
{
    int result=-1;

	void* conn = ipc_connect();
	if(!conn) return -1;
	NSDictionary* rep=nil;
	int req = ipc_request(conn, BSD_REQ_ENABLE_JIT, @{@"pid":@(pid)}, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
        if(resultObj) result = resultObj.intValue;
	}
	ipc_close(conn);

	return result;
}

const char* bsd_getsbtoken()
{
	const char* result=NULL;

	void* conn = ipc_connect();
	if(!conn) return NULL;
	NSDictionary* rep=nil;
	int req = ipc_request(conn, BSD_REQ_GET_SBTOKEN, nil, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		result = strdup([rep[@"sbtoken"] UTF8String]);
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
	}
	ipc_close(conn);

	return result;
}

int bsd_opensshctl(bool run)
{
	int result = -1;

	void* conn = ipc_connect();
	if(!conn) return -1;
	NSDictionary* rep=nil;
	int req = ipc_request(conn, run ? BSD_REQ_SSH_START : BSD_REQ_SSH_STOP, nil, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	ipc_close(conn);

	return result;
}

int bsd_opensshcheck()
{
	int result = -1;

	void* conn = ipc_connect();
	if(!conn) return -1;
	NSDictionary* rep=nil;
	int req = ipc_request(conn, BSD_REQ_SSH_CHECK, nil, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	ipc_close(conn);

	return result;
}

int bsd_stopServer()
{
	int result = -1;

	void* conn = ipc_connect();
	if(!conn) return -1;
	NSDictionary* rep=nil;
	int req = ipc_request(conn, BSD_REQ_STOP_SERVER, nil, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	ipc_close(conn);

	return result;
}

int bsd_checkServer()
{
	int result = -1;

	void* conn = ipc_connect();
	if(!conn) return -1;
	NSDictionary* rep=nil;
	int req = ipc_request(conn, BSD_REQ_CHECK_SERVER, nil, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	ipc_close(conn);

	return result;
}

int bsd_varClean()
{
	int result = -1;

	void* conn = ipc_connect();
	if(!conn) return -1;
	NSDictionary* rep=nil;
	int req = ipc_request(conn, BSD_REQ_VAR_CLEAN, @{@"bundleIdentifier":NSBundle.mainBundle.bundleIdentifier}, &rep);
	SYSLOG("ipc_request=%d", req);
	if(req == 0) {
		SYSLOG("ipc reponse: %s", rep.debugDescription.UTF8String);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	ipc_close(conn);

	return result;
}
