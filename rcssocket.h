#ifndef RCSSOCKET_H
#define RCSSOCKET_H

typedef struct client
{
	u_long ipaddr;
	int syned;
	int acked;
};

typedef struct asocket
{
	int sockindex;		// Used for multiplexing the asocket into a particular socket
	u_long clientIp;
} asocket;

typedef struct rcssocket {
	int sockfd;
	int hasConnectionRequest;
	int hasSocketData;
	int listening;
	struct sockaddr_in *client;
} rcssocket;

#endif
