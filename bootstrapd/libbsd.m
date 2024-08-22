
#include "../bootstrapd/ipc.h"
#include "../bootstrapd/bootstrapd.h"
#include "../bootstrapd/common.h"

int bsd_enableJIT()
{
    int result=-1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_ENABLE_JIT, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%@", rep);
		NSNumber* resultObj = rep[@"result"];
        if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}

extern int ipc_log_enabled;
int bsd_enableJIT2(pid_t pid)
{
	ipc_log_enabled=0;

    int result=-1;

	int sd = connect_to_server();
	if(sd <= 0) return -1;
	int req = request(sd, BSD_REQ_ENABLE_JIT2, @{@"pid":@(pid)});
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		SYSLOG("reponse=%@", rep);
		NSNumber* resultObj = rep[@"result"];
        if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	ipc_log_enabled=1;
	
	return result;
}

const char* bsd_getsbtoken()
{
	const char* result=nil;

	int sd = connect_to_server();
	if(sd <= 0) return NULL;
	int req = request(sd, BSD_REQ_GET_SBTOKEN, nil);
	SYSLOG("request=%d", req);
	if(req == 0) {
		NSDictionary* rep = reponse(sd);
		result = [rep[@"sbtoken"] UTF8String];
		SYSLOG("reponse=%@", rep);
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
		SYSLOG("reponse=%@", rep);
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
		SYSLOG("reponse=%@", rep);
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
		SYSLOG("reponse=%@", rep);
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
		SYSLOG("reponse=%@", rep);
		NSNumber* resultObj = rep[@"result"];
		if(resultObj) result = resultObj.intValue;
	}
	close(sd);

	return result;
}
