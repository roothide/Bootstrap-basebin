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


#define printf(...)	NSLog(@ __VA_ARGS__)
#define perror(x) NSLog(@"%s : %s", x, strerror(errno))


#define BSD_PORT_PATH jbroot("/basebin/.bootstrapd.port")

#define BSD_REQ_ID_KEY		"key"
#define BSD_REQ_PID_KEY		"pid"
#define BSD_REQ_CHECK_KEY	"check"
#define BSD_REQ_DATA_KEY	"value"


pid_t socket_get_pid(int sd)
{
	pid_t pid=-1;
	socklen_t pidlen=sizeof(pid);
	getsockopt(sd, 0, LOCAL_PEERPID, &pid, &pidlen);
	return pid;
}

uid_t socket_get_uid(int sd)
{
	uid_t uid=-1; gid_t gid=-1;
	getpeereid(sd, &uid, &gid);
	return uid;
}

gid_t socket_get_gid(int sd)
{
	uid_t uid=-1; gid_t gid=-1;
	getpeereid(sd, &uid, &gid);
	return gid;
}

int socket_get_audit_token(int sd, audit_token_t* audit_token)
{
	socklen_t len = sizeof(*audit_token);
	int ret = getsockopt(sd, SOL_LOCAL, LOCAL_PEERTOKEN, &audit_token, &len);
	return ret;
}



int recvbuf(int sd, void* buffer, int bufsize)
{
	assert(bufsize <= 4096); //net.local.stream.recvspace?

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
	
	while((rlen=recvmsg(sd, &msg, 0))<=0 && errno==EINTR); //may be interrupted by ptrace
	
	NSLog(@"recvbuf %p %d %d, %s", buffer, bufsize, rlen, rlen>0?"":strerror(errno));
	
	//rlen=0 if client close unexcept, assert(rlen > 0);

	return rlen;
}

int sendbuf(int sd, void* buffer, int bufsize)
{
	NSLog(@"sendbuf %d %p %d", sd, buffer, bufsize);

	assert(bufsize <= 4096); //net.local.stream.sendspace?

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

    int slen = sendmsg(sd, &msg, 0);
	
	//slen=0 if server close unexcept //assert(slen == bufsize);

	return slen;
}

int reply(int socket, NSDictionary* msg)
{
	NSLog(@"reply %d %@", socket, msg);

    if(msg) {
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:msg format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
        assert(data != nil);
        
        int slen = sendbuf(socket, (void*)data.bytes, data.length);

        // auto close here (async with main server)
        NSLog(@"close client %d", socket);
        close(socket);

        if(slen != data.length)
        {
            return -1;
        }
    } else {
        // auto close here (async with main server)
        NSLog(@"close client %d", socket);
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
	assert(data != nil);
	
	if(sendbuf(socket, (void*)data.bytes, data.length) != data.length)
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

int start_run_server(int (*callback)(int socket, pid_t pid, int reqId, NSDictionary* msg))
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

	//listen sockfd
	if(listen(sd, 128) < 0) {
		perror("listen");
		close(sd);
		return 1;
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

		NSLog(@"new client %d", cd);

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

	int ret = connect(sd, (struct sockaddr*)&addr, sizeof(addr));
	if(ret < 0) {
		perror("connect");
		close(sd);
		return -1;
	}

	return sd;
}

