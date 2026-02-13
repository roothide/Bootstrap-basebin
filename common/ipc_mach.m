#include <private/bsm/audit.h>
#include <Foundation/Foundation.h>
//objc-arc
#undef xpc_release
#define xpc_release(x)
#undef dispatch_release
#define dispatch_release(x)

#include <bootstrap.h>
#include <xpc/xpc.h>
#include "common.h"
#include "ipc.h"

#include <roothide.h>

#define dbglog(...) do { if (ipc_log_enabled) { SYSLOG(__VA_ARGS__); } } while (0)
#define errlog(...) do { if (ipc_log_enabled) { SYSERR(__VA_ARGS__); } } while (0)
#define perror(x)   do { if (ipc_log_enabled) { SYSERR("%s : %s", x, strerror(errno)); } } while (0)

//`snprintf` doesn't work during fork()
static void make_service_name(char* buffer, size_t buflen, const char* name)
{
	strlcpy(buffer, name, buflen);
	strlcat(buffer, "-", buflen);

	const char hex_digits[] = "0123456789ABCDEF";

	char temp[17];
	for (int i = 0; i < 16; i++) {
		temp[i] = '0';
	}
	temp[16] = '\0';

	int index = 15;
	uint64_t num = jbrand();
	while (num > 0 && index >= 0) {
		temp[index--] = hex_digits[num % 16];
		num /= 16;
	}

	strlcat(buffer, temp, buflen);
}

void* mach_ipc_connect()
{
	char service_name[256]={0};
	make_service_name(service_name, sizeof(service_name), "com.roothide.bootstrapd");

	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_look_up(bootstrap_port, service_name, &port);
	if(kr != KERN_SUCCESS || !MACH_PORT_VALID(port)) {
		errlog("mach_ipc: bootstrap_check_in (%s) port=%x kr=%x,%s", service_name, port, kr, bootstrap_strerror(kr));
		return NULL;
	}

	return (void*)(uintptr_t)port;
}

int mach_ipc_close(void* connection)
{
	mach_port_t port = (mach_port_t)(uintptr_t)connection;
	if(mach_port_deallocate(mach_task_self(), port) != KERN_SUCCESS) {
		errlog("mach_ipc: mach_port_deallocate failed");
		return -1;
	}
	return 0;
}

int mach_ipc_request(void* connection, int reqId, NSDictionary* request, NSDictionary** reply)
{
	dbglog("mach_ipc: request %d %s", reqId, request.debugDescription.UTF8String);

	int retval = 0;

	mach_port_t port = (mach_port_t)(uintptr_t)connection;

	request = request ?: @{};
	
	NSError* err=nil;
	NSData *data = [NSPropertyListSerialization dataWithPropertyList:request format:NSPropertyListBinaryFormat_v1_0 options:0 error:&err];
	if(!data) {
		ABORT("mach_ipc: serialization err=%s", err.debugDescription.UTF8String);
	}

	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "reqid", reqId);
	xpc_dictionary_set_data(message, "payload", data.bytes, data.length);

	xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
	if(pipe)
	{
		xpc_object_t xreply = NULL;
		int err = xpc_pipe_routine(pipe, message, &xreply);
		if(err==0)
		{
			ASSERT(xreply != NULL);

			size_t payload_size = 0;
			const void* payload_data = xpc_dictionary_get_data(xreply, "payload", &payload_size);

			if(payload_data && payload_size>0)
			{
				NSError* nserr=nil;
				data = [NSData dataWithBytes:payload_data length:payload_size];
				NSDictionary* repMsg = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:&nserr];
				if(!repMsg) {
					ABORT("mach_ipc: deserialization err=%s", nserr.debugDescription.UTF8String);
				}
				*reply = repMsg;
			}
			else
			{
				errlog("mach_ipc: invalid reply payload");
				retval = -1;
			}

			xpc_release(xreply);
		}
		else {
			retval = err;
		}
	}
	else
	{
		errlog("mach_ipc: xpc_pipe_create_from_port failed");
		retval = -2;
	}

	xpc_release(message);
	xpc_release(pipe);

	return retval;
}

int mach_ipc_reply(ipc_handle* handle, NSDictionary* msg)
{
	dbglog("mach_ipc: reply handle=%p msg=%s", handle, msg.debugDescription.UTF8String);

	int retval = 0;

	msg = msg ?: @{};

	xpc_object_t message = CFBridgingRelease(handle->cookie);

	xpc_object_t reply = xpc_dictionary_create_reply(message);

	NSData* data = [NSPropertyListSerialization dataWithPropertyList:msg format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
	ASSERT(data != nil);

	xpc_dictionary_set_data(reply, "payload", data.bytes, data.length);

	int err = xpc_pipe_routine_reply(reply);
	if (err != 0) {
		errlog("mach_ipc: xpc_pipe_routine_reply failed: %d", err);
		retval = -1;
	}

	xpc_release(message);
	xpc_release(reply);
	free(handle);

	return retval;
}

static ipc_handle* mach_ipc_handle_alloc(xpc_object_t message)
{
	ipc_handle* handle = malloc(sizeof(ipc_handle));
	handle->cookie = (void*)CFBridgingRetain(message);
	handle->reply = mach_ipc_reply;
	return handle;
}

int mach_ipc_run_server(ipc_handler handler)
{
	char service_name[256]={0};
	make_service_name(service_name, sizeof(service_name), "com.roothide.bootstrapd");
	dbglog("mach_ipc: starting server: %s", service_name);

	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_check_in(bootstrap_port, service_name, &port);
	ASSERT(kr==KERN_SUCCESS && MACH_PORT_VALID(port));

	static dispatch_source_t source; //retain the dispatch source
		source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)port, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH,0));
	dispatch_source_set_event_handler(source, ^{
		dbglog("mach_ipc: received message\n");

		mach_port_t port = (mach_port_t)dispatch_source_get_handle(source);

		xpc_object_t message = NULL;
		int err = xpc_pipe_receive(port, &message);
		if (err != 0) {
			errlog("mach_ipc: xpc_pipe_receive error %d", err);
			return;
		}

		if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) 
		{
			ipc_handle* handle = mach_ipc_handle_alloc(message);

			audit_token_t auditToken = {0};
			xpc_dictionary_get_audit_token(message, &auditToken);

			uint64_t reqId = xpc_dictionary_get_uint64(message, "reqid");

			size_t payload_size = 0;
			const void* payload_data = xpc_dictionary_get_data(message, "payload", &payload_size);
			if(payload_data && payload_size>0)
			{
				NSError* err=nil;
				NSData* data = [NSData dataWithBytes:payload_data length:payload_size];
				NSDictionary* msg = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:&err];
				if(msg) {
					handler(handle, audit_token_to_pid(auditToken), reqId, msg);
				} else {
					errlog("mach_ipc: deserialization err=%s", err.debugDescription.UTF8String);
					mach_ipc_reply(handle, nil);
				}
			} else {
				errlog("mach_ipc: invalid message payload");
				mach_ipc_reply(handle, nil);
			}
		}
		else
		{
			errlog("mach_ipc: invalid message type");
		}

		xpc_release(message);
	});

	dispatch_resume(source);

	while(!ipc_server_stop_flag)
	{
		sleep(1);
	}

	dispatch_source_cancel(source);
	dispatch_release(source);

	return 0;
}
