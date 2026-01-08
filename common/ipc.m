#include <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#import <mach/mach.h>

#include <bootstrap.h>
#include <roothide.h>
#include "common.h"
#include "ipc.h"

#define printf(...) do { if (ipc_log_enabled) { SYSLOG(__VA_ARGS__); } } while (0)
#define errlog(...) do { if (ipc_log_enabled) { SYSERR(__VA_ARGS__); } } while (0)
#define perror(x)   do { if (ipc_log_enabled) { SYSERR("%s : %s", x, strerror(errno)); } } while (0)

#define BSD_PORT_PATH jbroot("/basebin/.bootstrapd.port")

#define BSD_REQ_ID_KEY		"key"
#define BSD_REQ_PID_KEY		"pid"
#define BSD_REQ_CHECK_KEY	"check"
#define BSD_REQ_DATA_KEY	"value"


bool ipc_log_enabled=true;
bool server_stop_flag=false;

bool set_ipclog_enabled(bool enabled)
{
    bool old = ipc_log_enabled;
    ipc_log_enabled = enabled;
    return old;
}

int recvbuf(int sd, void* buffer, int bufsize)
{
    ASSERT(bufsize <= 4096); //net.local.stream.recvspace?

    struct iovec   iov[1];
    iov[0].iov_base = buffer;
    iov[0].iov_len = bufsize;

    struct msghdr   msg = {0};

    msg.msg_name   = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov    = iov;
    msg.msg_iovlen = 1;

    msg.msg_control        = NULL;
    msg.msg_controllen     = 0;

    int rlen = 0;
    
    while((rlen=recvmsg(sd, &msg, 0))<0 && errno==EINTR){}; //may be interrupted by ptrace
    
    printf("recvbuf %p %d/%d, %s", buffer, bufsize, rlen, rlen>=0?"":strerror(errno));
    
    //rlen=0 if client close unexpected, ASSERT(rlen > 0);

    return rlen;
}

int sendbuf(int sd, void* buffer, int bufsize)
{
    printf("sendbuf %d %p %d", sd, buffer, bufsize);

    ASSERT(bufsize <= 4096); //net.local.stream.sendspace?

    struct iovec   iov[1];
    iov[0].iov_base = buffer;
    iov[0].iov_len = bufsize;

    struct msghdr   msg = {0};

    msg.msg_name   = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov    = iov;
    msg.msg_iovlen = 1;

    msg.msg_control        = NULL;
    msg.msg_controllen     = 0;

    int slen = 0;
    while((slen=sendmsg(sd, &msg, 0))<0 && errno==EINTR){}; //may be interrupted by signal
    if(slen != bufsize) perror("sendmsg");
    
    //slen=0 if server close unexpected //ASSERT(slen == bufsize);

    return slen;
}

int reply(int socket, NSDictionary* msg)
{
    printf("reply %d %s", socket, msg.debugDescription.UTF8String);

    if(msg) {
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:msg format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        ASSERT(data != nil);
        
        int slen = sendbuf(socket, (void*)data.bytes, data.length);

        // auto close here (async with main server)
        printf("close client %d", socket);
        close(socket);

        if(slen != data.length)
        {
            return -1;
        }
    } else {
        // auto close here (async with main server)
        printf("close client %d", socket);
        close(socket);
    }

    return 0;
}

NSDictionary* reponse(int socket)
{
    int bufsize = 4096;
    void* buffer = malloc(bufsize);
    int size = recvbuf(socket, buffer, bufsize);

    NSDictionary* repMsg = nil;
    if(size > 0) {
        NSData* data = [NSData dataWithBytesNoCopy:buffer length:size];
        repMsg = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
        printf("reponse %s", repMsg.debugDescription.UTF8String);
        //dataWithBytesNoCopy autorelease //free(buffer)
    }
    else
    {
        free(buffer);
    }
    return repMsg;
}


int request(int socket, int reqId, NSDictionary* msg)
{
    printf("request %d %s", reqId, msg.debugDescription.UTF8String);

    NSDictionary* reqMsg = @{
        @(BSD_REQ_ID_KEY) : @(reqId),
        @(BSD_REQ_PID_KEY) : @(getpid()),
        @(BSD_REQ_CHECK_KEY) : @(jbrand()),
        @(BSD_REQ_DATA_KEY) : msg ? msg : @{}
    };

    NSError* err=nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:reqMsg format:NSPropertyListBinaryFormat_v1_0 options:0 error:&err];
    if(!data) {
        errlog("serialization err=%s", err.debugDescription.UTF8String);
        abort();
    }
    
    if(sendbuf(socket, (void*)data.bytes, data.length) != data.length)
    {
        return -1;
    }

    return 0;
}

int set_stop_server()
{
    if(server_stop_flag) return -1;
    server_stop_flag = true;
    return 0;
}

void start_mach_server()
{
    char service_name[256]={0};
    snprintf(service_name, sizeof(service_name), "com.roothide.bootstrapd-%016llX", jbrand());

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_check_in(bootstrap_port, service_name, &port);
    ASSERT(kr==KERN_SUCCESS && MACH_PORT_VALID(port));

    static dispatch_source_t source; //retain the dispatch source
     source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)port, 0, dispatch_get_global_queue(0,0));
    dispatch_source_set_event_handler(source, ^{
        mach_port_t port = (mach_port_t)dispatch_source_get_handle(source);

        xpc_object_t message = nil;
        int err = xpc_pipe_receive(port, &message);
        if (err != 0) {
            errlog("xpc_pipe_receive error %d", err);
            abort();
        }

        xpc_object_t reply = xpc_dictionary_create_reply(message);
        xpc_dictionary_set_uint64(reply, "ack", 1);
        err = xpc_pipe_routine_reply(reply);
        if (err != 0) {
            errlog("Error %d sending response", err);
            abort();
        }
    });

    dispatch_resume(source);
}

int run_ipc_server(int (*callback)(int socket, pid_t pid, int reqId, NSDictionary* msg))
{
    //unlink the old one
    unlink(BSD_PORT_PATH);

     int sd = socket(AF_INET, SOCK_STREAM, 0);
    if(sd < 0) {
        perror("socket");
        return 1;
    }

    int option_value = 1; /* Set NOSIGPIPE to ON */
    if (setsockopt (sd, SOL_SOCKET, SO_NOSIGPIPE, &option_value, sizeof (option_value)) < 0) {
        perror ("setsockopt");
        return 1;
    }

    struct sockaddr_in addr;
    
    while(true)
    {
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = 0;
        addr.sin_port = htons(1001+arc4random()%40000);
        
        //bind sockfd & addr
        if(bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            
            if(errno == EADDRINUSE)
                continue;
            
            perror("bind");
            close(sd);
            return 1;
        }
        
        break;
    }

    socklen_t addrlen = sizeof(addr);
    if (getsockname(sd, (struct sockaddr *)&addr, &addrlen) < 0) {
        perror("getsockname");
        close(sd);
        return 1;
    }
    
    printf("server %s : %d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    printf("bind port=%d", ntohs(addr.sin_port));

    int pd = open(BSD_PORT_PATH, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if(pd < 0) {
        perror("open BSD_PORT_PATH");
        close(sd);
        return 1;
    }

    write(pd, &addr, addrlen);
    close(pd);

    //listen sockfd
    if(listen(sd, 128) < 0) {
        perror("listen");
        close(sd);
        return 1;
    }

    if(__builtin_available(iOS 16.0, *))
    {
        if(get_real_ppid() == 1)
        {
            start_mach_server();
        }
    }

    int bufsize = 4096;
    void* buffer = malloc(bufsize);

    while(true)
    {
        if(server_stop_flag) break;

        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int cd = accept(sd, (struct sockaddr*)&addr, &len);
        if(cd < 0) {
            perror("accept");
            close(sd);
            return 1;
        }

        printf("new client %d", cd);

        int size = recvbuf(cd, buffer, bufsize);
        if(size > 0) { @autoreleasepool {

            NSData* data = [NSData dataWithBytes:buffer length:size];
            NSDictionary* msg = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];

            NSDictionary* reqMsg = msg[@(BSD_REQ_DATA_KEY)];
            NSNumber* reqIdObj = msg[@(BSD_REQ_ID_KEY)];
            NSNumber* checkObj = msg[@(BSD_REQ_CHECK_KEY)];
            NSNumber* pidObj = msg[@(BSD_REQ_PID_KEY)];
            
            if(checkObj.unsignedLongLongValue == jbrand())
            {
                //close(cd) by reply()
                callback(cd, pidObj.integerValue, reqIdObj.integerValue, reqMsg);
            } else {
                close(cd);
            }
        }} else {
            close(cd);
        }
    }

    free(buffer);

    close(sd);

    unlink(BSD_PORT_PATH);

    return 0;
}

#include <poll.h>
int check_conn(int sock)
{
    struct pollfd fd;

    fd.fd = sock;
    fd.events = POLLOUT;

    while ( poll (&fd, 1, -1) == -1 ) {
        if( errno != EINTR ){
            perror("poll");
            return -1;
        }
    }

    int err = 0;
    socklen_t len = sizeof(err);
    if ( getsockopt (sock, SOL_SOCKET, SO_ERROR,
                     &err,
                     &len) == -1 ) {
                perror("getsockopt");
        return -1;
    }

    if(err != 0) {
        perror("SO_ERROR");
        return -1;
    }

    return 0;
}

int connect_to_server()
{
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if(sd < 0) {
        perror("socket");
        return -1;
    }

    int option_value = 1; /* Set NOSIGPIPE to ON */
    if (setsockopt(sd, SOL_SOCKET, SO_NOSIGPIPE, &option_value, sizeof (option_value)) < 0) {
        perror ("setsockopt");
        return -1;
    }

    struct sockaddr_in addr;

    int pd = open(BSD_PORT_PATH, O_RDONLY);
    if(pd < 0) {
        perror("open BSD_PORT_PATH");
        close(sd);
        return -1;
    }

    if(read(pd, &addr, sizeof(addr)) < sizeof(addr)) {
        perror("read BSD_PORT_PATH");
        close(sd);
        return -1;
    }

    close(pd);

    printf("server %s : %d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    
    int ret = connect(sd, (struct sockaddr*)&addr, sizeof(addr));
    //may be interrupted by signal
    if(ret<0 && (errno!=EINTR || check_conn(sd)!=0)) {
        perror("connect");
        close(sd);
        return -1;
    }

    return sd;
}
