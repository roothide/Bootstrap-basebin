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

#include <bootstrap.h>
#include <roothide.h>
#include "common.h"
#include "ipc.h"

#define dbglog(...) do { if (ipc_log_enabled) { SYSLOG(__VA_ARGS__); } } while (0)
#define errlog(...) do { if (ipc_log_enabled) { SYSERR(__VA_ARGS__); } } while (0)
#define perror(x)   do { if (ipc_log_enabled) { SYSERR("%s : %s", x, strerror(errno)); } } while (0)

#define BSD_PORT_PATH jbroot("/basebin/.bootstrapd.port")

#define BSD_REQ_ID_KEY		"key"
#define BSD_REQ_PID_KEY		"pid"
#define BSD_REQ_CHECK_KEY	"check"
#define BSD_REQ_DATA_KEY	"value"

static int recvbuf(int sd, void* buffer, int bufsize)
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
    
    dbglog("socket_ipc: recvbuf %p %d/%d, %s", buffer, bufsize, rlen, rlen>=0?"":strerror(errno));
    
    //rlen=0 if client close unexpected, ASSERT(rlen > 0);

    return rlen;
}

static int sendbuf(int sd, void* buffer, int bufsize)
{
    dbglog("socket_ipc: sendbuf %d %p %d", sd, buffer, bufsize);

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
    if(slen != bufsize) perror("socket_ipc: sendmsg");
    
    //slen=0 if server close unexpected //ASSERT(slen == bufsize);

    return slen;
}

int socket_ipc_reply(ipc_handle* handle, NSDictionary* msg)
{
    int socket = (int)(uintptr_t)handle->cookie;
    dbglog("socket_ipc: reply conn=%d msg=%s", socket, msg.debugDescription.UTF8String);

    int retval = 0;
    
    if(msg) {
        NSData* data = [NSPropertyListSerialization dataWithPropertyList:msg format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        ASSERT(data != nil);
        
        int slen = sendbuf(socket, (void*)data.bytes, data.length);

        // auto close here (async with main server)
        dbglog("socket_ipc: close client %d", socket);
        close(socket);

        if(slen != data.length)
        {
            errlog("socket_ipc: sendbuf failed");
            retval = -1;
        }
    } else {
        // auto close here (async with main server)
        dbglog("socket_ipc: close client %d", socket);
        close(socket);
    }

    free(handle);

    return retval;
}

int socket_ipc_request(void* connection, int reqId, NSDictionary* request, NSDictionary** reply)
{
    int socket = (int)(uintptr_t)connection;
    dbglog("socket_ipc: request %d %s", reqId, request.debugDescription.UTF8String);

    NSDictionary* reqMsg = @{
        @(BSD_REQ_ID_KEY) : @(reqId),
        @(BSD_REQ_PID_KEY) : @(getpid()),
        @(BSD_REQ_CHECK_KEY) : @(jbrand()),
        @(BSD_REQ_DATA_KEY) : request ? request : @{}
    };

    NSError* err=nil;
    NSData* data = [NSPropertyListSerialization dataWithPropertyList:reqMsg format:NSPropertyListBinaryFormat_v1_0 options:0 error:&err];
    if(!data) {
        ABORT("socket_ipc: serialization err=%s", err.debugDescription.UTF8String);
    }
    
    if(sendbuf(socket, (void*)data.bytes, data.length) != data.length)
    {
        return -1;
    }

    int bufsize = 4096;
    void* buffer = malloc(bufsize);
    int size = recvbuf(socket, buffer, bufsize);
    if(size <= 0) {
        free(buffer);
        return -2;
    }

    err=nil;
    data = [NSData dataWithBytesNoCopy:buffer length:size];
    NSDictionary* repMsg = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:&err];
    if(!repMsg) {
        ABORT("socket_ipc: deserialization err=%s", err.debugDescription.UTF8String);
    }
    //dbglog("socket_ipc: reponse=%s", repMsg.debugDescription.UTF8String);
    //dataWithBytesNoCopy autorelease //free(buffer)
    *reply = repMsg;

    return 0;
}

ipc_handle* socket_ipc_handle_alloc(int socket)
{
    ipc_handle* handle = malloc(sizeof(ipc_handle));
    handle->cookie = (void*)(uintptr_t)socket; //close by socket_ipc_reply()
    handle->reply = socket_ipc_reply;
    return handle;
}

int socket_ipc_run_server(ipc_handler handler)
{
    //unlink the old one
    unlink(BSD_PORT_PATH);

     int sd = socket(AF_INET, SOCK_STREAM, 0);
    if(sd < 0) {
        perror("socket_ipc: socket");
        return 1;
    }

    int option_value = 1; /* Set NOSIGPIPE to ON */
    if (setsockopt (sd, SOL_SOCKET, SO_NOSIGPIPE, &option_value, sizeof (option_value)) < 0) {
        perror ("socket_ipc: setsockopt");
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
            
            perror("socket_ipc: bind");
            close(sd);
            return 1;
        }
        
        break;
    }

    socklen_t addrlen = sizeof(addr);
    if (getsockname(sd, (struct sockaddr *)&addr, &addrlen) < 0) {
        perror("socket_ipc: getsockname");
        close(sd);
        return 1;
    }
    
    dbglog("socket_ipc: server %s : %d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    dbglog("socket_ipc: bind port=%d", ntohs(addr.sin_port));

    int pd = open(BSD_PORT_PATH, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if(pd < 0) {
        perror("socket_ipc: open BSD_PORT_PATH");
        close(sd);
        return 1;
    }

    write(pd, &addr, addrlen);
    close(pd);

    //listen sockfd
    if(listen(sd, 128) < 0) {
        perror("socket_ipc: listen");
        close(sd);
        return 1;
    }

    if(launchd_exploit_available())
    {
        if(get_real_ppid() == 1)
        {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                mach_ipc_run_server(handler);
            });
        }
    }

    int bufsize = 4096;
    void* buffer = malloc(bufsize);

    while(true)
    {
        if(ipc_server_stop_flag) break;

        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int cd = accept(sd, (struct sockaddr*)&addr, &len);
        if(cd < 0) {
            perror("socket_ipc: accept");
            close(sd);
            return 1;
        }

        dbglog("socket_ipc: new client %d", cd);

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
                ipc_handle* handle = socket_ipc_handle_alloc(cd);
                handler(handle, pidObj.integerValue, reqIdObj.integerValue, reqMsg);
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
static int check_conn(int sock)
{
    struct pollfd fd;

    fd.fd = sock;
    fd.events = POLLOUT;

    while ( poll (&fd, 1, -1) == -1 ) {
        if( errno != EINTR ){
            perror("socket_ipc: poll");
            return -1;
        }
    }

    int err = 0;
    socklen_t len = sizeof(err);
    if ( getsockopt (sock, SOL_SOCKET, SO_ERROR,
                     &err,
                     &len) == -1 ) {
                perror("socket_ipc: getsockopt");
        return -1;
    }

    if(err != 0) {
        perror("socket_ipc: SO_ERROR");
        return -1;
    }

    return 0;
}

void* socket_ipc_connect()
{
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if(sd < 0) {
        perror("socket_ipc: socket");
        return NULL;
    }

    int option_value = 1; /* Set NOSIGPIPE to ON */
    if (setsockopt(sd, SOL_SOCKET, SO_NOSIGPIPE, &option_value, sizeof (option_value)) < 0) {
        perror ("socket_ipc: setsockopt");
        return NULL;
    }

    struct sockaddr_in addr;

    int pd = open(BSD_PORT_PATH, O_RDONLY);
    if(pd < 0) {
        perror("socket_ipc: open BSD_PORT_PATH");
        close(sd);
        return NULL;
    }

    if(read(pd, &addr, sizeof(addr)) < sizeof(addr)) {
        perror("socket_ipc: read BSD_PORT_PATH");
        close(sd);
        return NULL;
    }

    close(pd);

    dbglog("socket_ipc: server %s : %d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    
    int ret = connect(sd, (struct sockaddr*)&addr, sizeof(addr));
    //may be interrupted by signal
    if(ret<0 && (errno!=EINTR || check_conn(sd)!=0)) {
        perror("socket_ipc: connect");
        close(sd);
        return NULL;
    }

    return (void*)(uintptr_t)sd;
}

int socket_ipc_close(void* connection)
{
    int socket = (int)(uintptr_t)connection;
    return close(socket);
}
