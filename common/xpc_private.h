#ifndef ROOTHIDE_XPC_PRIVATE_H
#define ROOTHIDE_XPC_PRIVATE_H
#include <xpc/xpc.h>
#include <mach/mach.h>

char *xpc_strerror (int);

#if !__has_include(<xpc/private.h>)
extern xpc_object_t xpc_create_from_plist(void *data, size_t size);
//real xpc_pipe_receive
//extern int xpc_pipe_receive(mach_port_t port, XPC_GIVES_REFERENCE xpc_object_t *message, bool timeout);
extern XPC_RETURNS_RETAINED xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
extern int xpc_pipe_simpleroutine(xpc_object_t pipe, xpc_object_t message);
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, XPC_GIVES_REFERENCE xpc_object_t *reply);
extern int xpc_pipe_routine_with_flags(xpc_object_t xpc_pipe, xpc_object_t inDict, XPC_GIVES_REFERENCE xpc_object_t *reply, uint32_t flags);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, XPC_GIVES_REFERENCE xpc_object_t *message);
typedef boolean_t (*xpc_pipe_mig_call_t)(mach_msg_header_t *request, mach_msg_header_t *reply);
kern_return_t xpc_pipe_try_receive(mach_port_t port, xpc_object_t *request, mach_port_t *out_port, xpc_pipe_mig_call_t mig_handler, mach_msg_size_t mig_size, uint64_t flags);
extern void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);
extern xpc_connection_t xpc_connection_create_mach_service_alias(const char *name, dispatch_queue_t targetq, uint64_t flags) asm("_xpc_connection_create_mach_service");
#define xpc_connection_create_mach_service xpc_connection_create_mach_service_alias
#endif

extern xpc_object_t xpc_mach_send_create(mach_port_t);
extern mach_port_t xpc_mach_send_get_right(xpc_object_t); //will deallocate the port when releasing xpc object
extern mach_port_t xpc_mach_send_copy_right(xpc_object_t);

extern xpc_object_t xpc_mach_recv_create(mach_port_t);
extern mach_port_t xpc_mach_recv_extract_right(xpc_object_t);

#endif // ROOTHIDE_XPC_PRIVATE_H