#ifndef RCSSOCKET_H
#define RCSSOCKET_H

typedef struct client
{
	u_long ipaddr;
	int syned;
	int acked;
} client;

typedef struct asocket
{
	int sockfd;		// Used for multiplexing the asocket into a particular socket
	u_long clientIp;
} asocket;

typedef struct rcssocket {
	int sockfd;
	int listening;
	int bound;
	u_long clientIp;
	u_long serverIp;
	unsigned short port;
	struct sockaddr_in *from;
} rcssocket;

#endif
