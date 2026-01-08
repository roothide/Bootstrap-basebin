#include <private/bsm/audit.h>

#include <unistd.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>

#include "common.h"
#include "jbclient.h"
#include "jailbreakd.h"

static int roothide_jailbroken_check(audit_token_t *callerToken, bool* jailbroken)
{
	*jailbroken = true;
	return 0;
}

static int roothide_palehide_present(audit_token_t *callerToken, bool* palehide)
{
	static bool result = false;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ 
		//...
	});

	*palehide = result;
	return 0;
}

static int roothide_blacklist_check(audit_token_t *callerToken, const char* checktype, xpc_object_t checkvalue, bool* blacklisted)
{
	if(strcmp(checktype, "pid")==0) {
		pid_t pid = (pid_t)xpc_uint64_get_value(checkvalue);
		if(pid > 1) {
			*blacklisted = isBlacklistedPid(pid);
			return 0;
		}
	} else if(strcmp(checktype, "path")==0) {
		const char* path = xpc_string_get_string_ptr(checkvalue);
		if(path) {
			*blacklisted = isBlacklistedPath(path);
			return 0;
		}
	} else if(strcmp(checktype, "bundle")==0) {
		const char* bundle = xpc_string_get_string_ptr(checkvalue);
		if(bundle) {
			*blacklisted = isBlacklistedApp(bundle);
			return 0;
		}
	} else {
		FileLogError("Invalid checktype: %s", checktype);
		return -1;
	}
	FileLogError("Failed to check blacklist for %s : %s", checktype, xpc_type_get_name(xpc_get_type(checkvalue)));
	return -1;
}

static int roothide_jailbreakd_lookup(audit_token_t *callerToken, xpc_object_t *portOut)
{
	*portOut = xpc_mach_send_create(jailbreakdClientPort());
	return 0;
}

static int roothide_jailbreakd_checkin(audit_token_t *callerToken, xpc_object_t *portOut)
{
	pid_t pid = audit_token_to_pid(*callerToken);
	uid_t uid = audit_token_to_euid(*callerToken);

	if(uid != 0) return -1;

	setJailbreakdProcess(pid);

	*portOut = xpc_mach_recv_create(jailbreakdServerPort());
	return 0;
}

int roothide_handle_launchd_xpc_msg(xpc_object_t xmsg);
int jbserver_received_xpc_message(xpc_object_t xmsg)
{
	if (xpc_get_type(xmsg) != XPC_TYPE_DICTIONARY) return -1;

	if(roothide_handle_launchd_xpc_msg(xmsg) != 0) return -1;

	if (!xpc_dictionary_get_value(xmsg, "jb-domain")) return -1;
	if (!xpc_dictionary_get_value(xmsg, "action")) return -1;

	audit_token_t clientToken = { 0 };
	xpc_dictionary_get_audit_token(xmsg, &clientToken);

	const char *desc = NULL;
	FileLogDebug("jbserver received xpc message from (%d) %s :\n%s", audit_token_to_pid(clientToken), proc_get_path(audit_token_to_pid(clientToken), NULL), (desc = xpc_copy_description(xmsg)));
	if (desc) free((void *)desc);

	uint64_t domainIdx = xpc_dictionary_get_uint64(xmsg, "jb-domain");
	uint64_t actionIdx = xpc_dictionary_get_uint64(xmsg, "action");

	int result = -1;

	xpc_object_t xreply = xpc_dictionary_create_reply(xmsg);

	if(domainIdx==JBS_DOMAIN_ROOTHIDE) switch(actionIdx)
	{
		case JBS_ROOTHIDE_JAILBROKEN_CHECK:
		{
			bool jailbroken = false;
			result = roothide_jailbroken_check(&clientToken, &jailbroken);
			xpc_dictionary_set_bool(xreply, "jailbroken", jailbroken);
			break;
		}
		case JBS_ROOTHIDE_PALEHIDE_PRESENT:
		{
			bool palehide = false;
			result = roothide_palehide_present(&clientToken, &palehide);
			xpc_dictionary_set_bool(xreply, "palehide", palehide);
			break;
		}
		case JBS_ROOTHIDE_BLACKLIST_CHECK:
		{
			const char* checktype = xpc_dictionary_get_string(xmsg, "checktype");
			xpc_object_t checkvalue = xpc_dictionary_get_value(xmsg, "checkvalue");
			bool blacklisted = false;
			result = roothide_blacklist_check(&clientToken, checktype, checkvalue, &blacklisted);
			xpc_dictionary_set_bool(xreply, "blacklisted", blacklisted);
			break;
		}
		case JBS_ROOTHIDE_JAILBREAKD_LOOKUP:
		{
			xpc_object_t portOut = NULL;
			result = roothide_jailbreakd_lookup(&clientToken, &portOut);
			if(portOut) {
				xpc_dictionary_set_value(xreply, "port", portOut);
				xpc_release(portOut);
			}
			break;
		}
		case JBS_ROOTHIDE_JAILBREAKD_CHECKIN:
		{
			xpc_object_t portOut = NULL;
			result = roothide_jailbreakd_checkin(&clientToken, &portOut);
			if(portOut) {
				xpc_dictionary_set_value(xreply, "port", portOut);
				xpc_release(portOut);
			}
			break;
		}
		default:
			FileLogError("Unknown roothide action: %llu", actionIdx);
			break;


	}

	xpc_dictionary_set_int64(xreply, "result", result);
	xpc_pipe_routine_reply(xreply);
	xpc_release(xreply);

	return 0;
}

