#ifdef __OBJC__
#include <Foundation/Foundation.h>
#endif

bool set_ipclog_enabled(bool enabled);

int connect_to_server();

int set_stop_server();

#ifdef __OBJC__
int run_ipc_server(int (*callback)(int socket, pid_t pid, int reqId, NSDictionary* msg));

int request(int socket, int reqId, NSDictionary* msg);
int reply(int socket, NSDictionary* msg);
NSDictionary* reponse(int socket);
#endif