#ifdef __OBJC__
#include <Foundation/Foundation.h>
#endif

extern bool ipc_log_enabled;
extern bool ipc_server_stop_flag;

bool ipc_set_log_enabled(bool enabled);

int ipc_set_stop_server();

#ifdef __OBJC__

typedef struct ipc_handle ipc_handle;

struct ipc_handle {
	void* cookie;
	int (*reply)(ipc_handle* handle, NSDictionary* msg);
};

typedef int (*ipc_handler)(ipc_handle* handle, pid_t pid, int reqId, NSDictionary* msg);

void* ipc_connect();
int ipc_close(void* connection);
int ipc_run_server(ipc_handler handler);
int ipc_request(void* connection, int reqId, NSDictionary* request, NSDictionary** reply);

//socket ipc
void* socket_ipc_connect();
int socket_ipc_close(void* connection);
int socket_ipc_run_server(ipc_handler handler);
int socket_ipc_request(void* connection, int reqId, NSDictionary* request, NSDictionary** reply);

//mach ipc
void* mach_ipc_connect();
int mach_ipc_close(void* connection);
int mach_ipc_run_server(ipc_handler handler);
int mach_ipc_request(void* connection, int reqId, NSDictionary* request, NSDictionary** reply);
#endif

/*
#define ipc_run_server socket_ipc_run_server
#define ipc_connect socket_ipc_connect
#define ipc_request socket_ipc_request
#define ipc_close socket_ipc_close
/*/
#define ipc_run_server mach_ipc_run_server
#define ipc_connect mach_ipc_connect
#define ipc_request mach_ipc_request
#define ipc_close mach_ipc_close
//*/
