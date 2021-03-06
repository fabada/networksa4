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
	struct sockaddr_in sockaddr;
} asocket;

typedef struct rcssocket {
	int sockfd;
	int listening;
	int bound;
	u_long clientIp;
	u_long serverIp;
	u_long ipaddr;
	unsigned short port;
	struct sockaddr_in sockaddr;
} rcssocket;

#endif
