
#include "jbclient.h"

#define OS_ALLOC_ONCE_KEY_MAX    100

struct _os_alloc_once_s {
	long once;
	void *ptr;
};

struct xpc_global_data {
	uint64_t    a;
	uint64_t    xpc_flags;
	mach_port_t    task_bootstrap_port;  /* 0x10 */
#ifndef _64
	uint32_t    padding;
#endif
	xpc_object_t    xpc_bootstrap_pipe;   /* 0x18 */
};

extern struct _os_alloc_once_s _os_alloc_once_table[];
extern void* _os_alloc_once(struct _os_alloc_once_s *slot, size_t sz, os_function_t init);

mach_port_t gJBServerCustomPort = MACH_PORT_NULL;

void jbclient_xpc_set_custom_port(mach_port_t serverPort)
{
	if (gJBServerCustomPort != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), gJBServerCustomPort);
	}
	gJBServerCustomPort = serverPort;
}

mach_port_t jbclient_mach_get_launchd_port(void)
{
	mach_port_t launchdPort = MACH_PORT_NULL;
	task_get_bootstrap_port(task_self_trap(), &launchdPort);
	return launchdPort;
}

xpc_object_t jbserver_xpc_send_dict(xpc_object_t xdict)
{
	xpc_object_t xreply = NULL;

	xpc_object_t xpipe = NULL;
	if (gJBServerCustomPort != MACH_PORT_NULL) {
		// Communicate with custom port if set
		xpipe = xpc_pipe_create_from_port(gJBServerCustomPort, 0);
	}
	else {
		// Else, communicate with launchd
		struct xpc_global_data* globalData = NULL;
		if (_os_alloc_once_table[1].once == -1) {
			globalData = _os_alloc_once_table[1].ptr;
		}
		else {
			globalData = _os_alloc_once(&_os_alloc_once_table[1], 472, NULL);
			if (!globalData) _os_alloc_once_table[1].once = -1;
		}
		if (!globalData) return NULL;
		if (!globalData->xpc_bootstrap_pipe) {
			mach_port_t launchdPort = jbclient_mach_get_launchd_port();
			if (launchdPort != MACH_PORT_NULL) {
				globalData->task_bootstrap_port = launchdPort;
				globalData->xpc_bootstrap_pipe = xpc_pipe_create_from_port(globalData->task_bootstrap_port, 0);
			}
		}
		if (!globalData->xpc_bootstrap_pipe) return NULL;
		xpipe = xpc_retain(globalData->xpc_bootstrap_pipe);
	}

	if (!xpipe) return NULL;
	int err = xpc_pipe_routine_with_flags(xpipe, xdict, &xreply, 0);
	xpc_release(xpipe);
	if (err != 0) {
		return NULL;
	}
	return xreply;
}

xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t xargs)
{
	bool ownsXargs = false;
	if (!xargs) {
		xargs = xpc_dictionary_create_empty();
		ownsXargs = true;
	}

	xpc_dictionary_set_uint64(xargs, "jb-domain", domain);
	xpc_dictionary_set_uint64(xargs, "action", action);

	xpc_object_t xreply = jbserver_xpc_send_dict(xargs);
	if (ownsXargs) {
		xpc_release(xargs);
	}

	return xreply;
}


mach_port_t jbclient_jailbreakd_lookup()
{
	mach_port_t port = MACH_PORT_NULL;
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_JAILBREAKD_LOOKUP, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			xpc_object_t portobj = xpc_dictionary_get_value(xreply, "port");
			if (portobj) {
				port = xpc_mach_send_copy_right(portobj);
			}
		}
		xpc_release(xreply);
	}
	return port;
}

mach_port_t jbclient_jailbreakd_checkin()
{
	mach_port_t port = MACH_PORT_NULL;
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_JAILBREAKD_CHECKIN, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			xpc_object_t portobj = xpc_dictionary_get_value(xreply, "port");
			if (portobj) {
				port = xpc_mach_recv_extract_right(portobj);
			}
		}
		xpc_release(xreply);
	}
	return port;
}

bool jbclient_roothide_jailbroken()
{
	bool jailbroken = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_JAILBROKEN_CHECK, xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			jailbroken = xpc_dictionary_get_bool(xreply, "jailbroken");
		}
		xpc_release(xreply);
	}

	return jailbroken;
}

bool jbclient_palehide_present()
{
	bool palehide = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_PALEHIDE_PRESENT, xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			palehide = xpc_dictionary_get_bool(xreply, "palehide");
		}
		xpc_release(xreply);
	}

	return palehide;
}

bool jbclient_blacklist_check_pid(pid_t pid)
{
	bool blacklisted = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(xargs, "checktype", "pid");
    xpc_dictionary_set_uint64(xargs, "checkvalue", pid);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_BLACKLIST_CHECK, xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			blacklisted = xpc_dictionary_get_bool(xreply, "blacklisted");
		}
		xpc_release(xreply);
	}

	return blacklisted;
}

bool jbclient_blacklist_check_path(const char* path)
{
	bool blacklisted = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(xargs, "checktype", "path");
    xpc_dictionary_set_string(xargs, "checkvalue", path);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_BLACKLIST_CHECK, xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			blacklisted = xpc_dictionary_get_bool(xreply, "blacklisted");
		}
		xpc_release(xreply);
	}

	return blacklisted;
}

bool jbclient_blacklist_check_bundle(const char* bundle)
{
	bool blacklisted = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(xargs, "checktype", "bundle");
    xpc_dictionary_set_string(xargs, "checkvalue", bundle);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_BLACKLIST_CHECK, xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			blacklisted = xpc_dictionary_get_bool(xreply, "blacklisted");
		}
		xpc_release(xreply);
	}

	return blacklisted;
}
