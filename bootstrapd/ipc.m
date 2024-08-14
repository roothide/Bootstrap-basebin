#include <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/stat.h>
#import <mach/mach.h>

#include <roothide.h>
#include "assert.h"

#ifndef BOOTSTRAPD
#define printf(...)
#define NSLog(...)
#else
#define printf(...)	NSLog(@ __VA_ARGS__)
#define perror(x) NSLog(@"%s : %s", x, strerror(errno))
#endif


#define BSD_PORT_PATH jbroot("/basebin/.bootstrapd.port")

#define BSD_REQ_ID_KEY		"key"
#define BSD_REQ_PID_KEY		"pid"
#define BSD_REQ_CHECK_KEY	"check"
#define BSD_REQ_DATA_KEY	"value"


struct sockaddr_in g_server_addr = {0};


int recvbuf(int sd, struct sockaddr_in* addr, void* buffer, int bufsize)
{
	ASSERT(bufsize <= 4096); //net.local.stream.recvspace?

    socklen_t addrlen = addr ? sizeof(*addr) : 0;
	
    int rlen;
	while((rlen=recvfrom(sd,buffer,bufsize,MSG_WAITALL,(struct sockaddr *)addr, &addrlen))<=0 && errno==EINTR){}; //may be interrupted by ptrace
	
	NSLog(@"recvbuf %p %d %d, %s", buffer, bufsize, rlen, rlen>0?"":strerror(errno));
	
	//rlen=0 if client close unexcept, ASSERT(rlen > 0);

	return rlen;
}

int sendbuf(int sd, struct sockaddr_in* addr, void* buffer, int bufsize)
{
	NSLog(@"sendbuf %d %p %d", sd, buffer, bufsize);

	ASSERT(bufsize <= 4096); //net.local.stream.sendspace?

    int slen = sendto(sd, buffer, bufsize, MSG_DONTWAIT, (struct sockaddr *)addr, addr ? sizeof(*addr) : 0);
	if(slen != bufsize) perror("sendto");
	
	//slen=0 if server close unexcept //ASSERT(slen == bufsize);

	return slen;
}

int reply(int socket, struct sockaddr_in* addr, NSDictionary* msg)
{
	NSLog(@"reply %d %@", socket, msg);

	if(!msg) msg = @{};

    NSData *data = [NSPropertyListSerialization dataWithPropertyList:msg format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    ASSERT(data != nil);
    
    int slen = sendbuf(socket, addr, (void*)data.bytes, data.length);

    if(slen != data.length)
    {
        return -1;
    }

	return 0;
}

NSDictionary* reponse(int socket)
{
	int bufsize = 4096;
	void* buffer = malloc(bufsize);
	int size = recvbuf(socket, &g_server_addr, buffer, bufsize);

	NSDictionary* repMsg = nil;
	if(size > 0) {
		NSData* data = [NSData dataWithBytesNoCopy:buffer length:size];
		repMsg = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];

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
	NSDictionary* reqMsg = @{ 
		@(BSD_REQ_ID_KEY) : @(reqId),
		@(BSD_REQ_PID_KEY) : @(getpid()),
		@(BSD_REQ_CHECK_KEY) : @(jbrand()),
		@(BSD_REQ_DATA_KEY) : msg ? msg : @{}
	};

	NSError* err=nil;
	NSData *data = [NSPropertyListSerialization dataWithPropertyList:reqMsg format:NSPropertyListBinaryFormat_v1_0 options:0 error:&err];
	//NSLog(@"err=%@", err);
	ASSERT(data != nil);
	
	if(sendbuf(socket, &g_server_addr, (void*)data.bytes, data.length) != data.length)
	{
		return -1;
	}

	return 0;
}


bool server_stop_flag=false;
int set_stop_server()
{
	if(server_stop_flag) return -1;
    server_stop_flag = true;
    return 0;
}

int run_ipc_server(int (*callback)(int socket, struct sockaddr_in* addr, pid_t pid, int reqId, NSDictionary* msg))
{	
	//unlink the old one
	unlink(BSD_PORT_PATH);

 	int sd = socket(AF_INET, SOCK_DGRAM, 0);
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
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0;
	addr.sin_port = 0;

	//bind sockfd & addr
	if(bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(sd);
		return 1;
	}

	socklen_t addrlen = sizeof(addr);
	if (getsockname(sd, (struct sockaddr *)&addr, &addrlen) < 0) {
		perror("getsockname");
		close(sd);
		return 1;
	}

	NSLog(@"bind port=%d", addr.sin_port);

	int pd = open(BSD_PORT_PATH, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if(pd < 0) {
		perror("open BSD_PORT_PATH");
		close(sd);
		return 1;
	}

	write(pd, &addr, addrlen);
	close(pd);

	int bufsize = 4096;
	void* buffer = malloc(bufsize);

	while(true)
	{
        if(server_stop_flag) break;

		int cd=sd;
        struct sockaddr_in client_addr;
		int size = recvbuf(cd, &client_addr, buffer, bufsize);
        
        NSLog(@"new client %d", cd);

		if(size > 0) { @autoreleasepool {

            NSData* data = [NSData dataWithBytes:buffer length:size];
            NSDictionary* msg = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];

            NSDictionary* reqMsg = msg[@(BSD_REQ_DATA_KEY)];
            NSNumber* reqIdObj = msg[@(BSD_REQ_ID_KEY)];
            NSNumber* checkObj = msg[@(BSD_REQ_CHECK_KEY)];
            NSNumber* pidObj = msg[@(BSD_REQ_PID_KEY)];
            
            if(checkObj.unsignedLongLongValue == jbrand())
            {
			    callback(cd, &client_addr, pidObj.integerValue, reqIdObj.integerValue, reqMsg);
            } else {
				NSLog(@"unknown connection %d", cd);
            }
		}} else {
			NSLog(@"unknown connection %d", cd);
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

int connect_to_server_timeout(int timeout)
{
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sd < 0) {
		perror("socket");
		return -1;
	}

	int option_value = 1; /* Set NOSIGPIPE to ON */
	if (setsockopt(sd, SOL_SOCKET, SO_NOSIGPIPE, &option_value, sizeof (option_value)) < 0) {
		perror ("SO_NOSIGPIPE");
		return -1;
	}
    
    struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		perror("SO_RCVTIMEO");
		close(sd);
		return -1;
	}

	int pd = open(BSD_PORT_PATH, O_RDONLY);
	if(pd < 0) {
		perror("open BSD_PORT_PATH");
		close(sd);
		return -1;
	}

	if(read(pd, &g_server_addr, sizeof(g_server_addr)) < sizeof(g_server_addr)) {
		perror("read BSD_PORT_PATH");
		close(sd);
		return -1;
	}

	close(pd);

	return sd;
}

int connect_to_server()
{
	return connect_to_server_timeout(5);
}
