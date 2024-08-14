#include <Foundation/Foundation.h>

int connect_to_server();
int connect_to_server_timeout(int timeout);

int run_ipc_server(int (*callback)(int socket, void* addr, pid_t pid, int reqId, NSDictionary* msg));
int set_stop_server();

int request(int socket, int reqId, NSDictionary* msg);
int reply(int socket, void* addr, NSDictionary* msg);
NSDictionary* reponse(int socket);

