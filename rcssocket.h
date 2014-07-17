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
	int hasConnectionRequest;
	int hasSocketData;
	int listening;
	int bound;
	int client;
	u_long clientIp;			// For server sockets
} rcssocket;

#endif
