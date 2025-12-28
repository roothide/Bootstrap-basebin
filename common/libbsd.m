
#include "ipc.h"
#include "libbsd.h"
#include "common.h"

#define printf(...) SYSLOG
#define perror(x)   SYSLOG("%s : %s", x, strerror(errno));

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
