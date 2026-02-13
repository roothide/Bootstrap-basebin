#include <Foundation/Foundation.h>
#include "ipc.h"

bool ipc_log_enabled=true;
bool ipc_server_stop_flag=false;

bool ipc_set_log_enabled(bool enabled)
{
    bool old = ipc_log_enabled;
    ipc_log_enabled = enabled;
    return old;
}

int ipc_set_stop_server()
{
    if(ipc_server_stop_flag) return -1;
    ipc_server_stop_flag = true;
    return 0;
}

/*
bool ipc_force_mach_ipc()
{
    return getenv("FORCE_MACH_IPC") != NULL;
}

void* ipc_connect()
{
    return ipc_force_mach_ipc() ? mach_ipc_connect() : socket_ipc_connect();
}

int ipc_close(void* connection)
{
    return ipc_force_mach_ipc() ? mach_ipc_close(connection) : socket_ipc_close(connection);
}

int ipc_run_server(ipc_handler handler)
{
    return ipc_force_mach_ipc() ? mach_ipc_run_server(handler) : socket_ipc_run_server(handler);
}

int ipc_request(void* connection, int reqId, NSDictionary* request, NSDictionary** reply)
{
    return ipc_force_mach_ipc() ? mach_ipc_request(connection, reqId, request, reply) : socket_ipc_request(connection, reqId, request, reply);
}
*/
