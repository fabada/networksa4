/* 
 * Mahesh V. Tripunitara
 * University of Waterloo
 *
 */
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include "rcssocket.h"
#include <map>
#include <cstring>

using namespace std;

extern int errno;

extern int ucpSocket();
extern int ucpBind(int , struct sockaddr_in *);
extern int ucpGetSockName(int, struct sockaddr_in *);
extern int ucpSetSockRecvTimeout(int, int);
extern int ucpSendTo(int, const void *, int, const struct sockaddr_in *);
extern ssize_t ucpRecvFrom(int, void *, int, struct sockaddr_in *);
extern int ucpClose(int);

map<int, rcssocket> sockets;
map<int, asocket> asockets;						// asockfd maps to the sockfd
map<int, client> clients;						// client status
int rcs_server_sockfd;

void initSocket(int sockfd) {
	sockets[sockfd].sockfd = sockfd;
	sockets[sockfd].listening = 0;
	sockets[sockfd].bound = 0;
	sockets[sockfd].clientIp = 0;
	sockets[sockfd].serverIp = 0;
	sockets[sockfd].port = 0;
}

/**
 * Init the asocket.
 * @param sockfd = socket file descriptor.
 * @param asockfd = accepted socket fd
 * @param ipaddr = client ip address
 */
void initASocket(int sockfd, int asockfd, u_long ipaddr) {
	asockets[asockfd].sockfd = sockfd;
	asockets[asockfd].clientIp = ipaddr;
}

map<u_long, client> initClientMap() {
	map<u_long, client> newMap;
	return newMap;
}

client initClient(u_long ipaddr) {
	client newClient;

	newClient.ipaddr = ipaddr;
	newClient.syned = 0;
	newClient.acked = 0;

	return newClient;
}

int rcsSocket()
{
	int sockfd = ucpSocket();
	initSocket(sockfd);

	return sockfd;
}

int rcsBind(int sockfd, struct sockaddr_in *addr) {
    if (ucpBind(sockfd, addr) == -1) {
		return -1;
    }

    sockets[sockfd].bound = 1;
    return 0;
}

int rcsListen(int sockfd) {
	// Find the rcsocket associated with the file descriptor
	sockets[sockfd].listening = 1;
	rcs_server_sockfd = sockfd;

	return 0;
}

int rcsGetSockName(int sockfd, struct sockaddr_in *addr)
{
	if (sockets.find(sockfd) == sockets.end()) {
		errno = EBADF;
		return -1;
	}
	return ucpGetSockName(sockfd, addr);
}

int rcsConnect(int sockfd, const struct sockaddr_in *server) {
	if (sockets.find(sockfd) == sockets.end()) {
		errno = EBADF;
		return -1;
	}
	if (sockets[sockfd].bound == 0) {
		errno = EBADF;
		return -1;
	}

	char synbuf[4] = "SYN";
	char ackbuf[4] = "ACK";
	char recvbuf[64];
	struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));

	// First syn, then ack. Use a loop in case of failure
	while (true) {
		if (ucpSendTo(sockfd, (void *)synbuf, 4, server) == -1) {
			return -1;
		}
		if (ucpRecvFrom(sockfd, (void *)recvbuf, 64, from) == -1) {
			return -1;
		}
		if (strcmp(recvbuf, "SYNACK") != 0) {
			continue;
		}
		if (ucpSendTo(sockfd, (void *)ackbuf, 4, server) == -1) {
			return -1;
		}
		break;
	}

	sockets[sockfd].serverIp = server.sin_addr.s_addr;
	sockets[sockfd].port = server.sin_port;

	free(from);
	from = NULL;
	return 0;
}

int rcsAccept(int sockfd, struct sockaddr_in *from) {
	char buffer[4];
	char sendbuf[7] = "SYNACK";
	char ackbuf[4] = "ACK";
	int status;
	int len = 4;
	u_long ipaddr;
	int asockfd;

	// Invalid socket
	if (sockets.find(sockfd) == sockets.end()) {
		errno = EBADF;
		return -1;
	}
	// Not listening
	if (sockets[sockfd].listening == 0) {
		errno = EINVAL;
		return -1;
	}

	while ((status = ucpRecvFrom(sockfd, (void *)buffer, len, from)) != -1) {
		ipaddr = from->sin_addr.s_addr;
		if (clients.find(sockfd) == clients.end()) {
			// New client
			clients[sockfd] = initClient(ipaddr);
		}

		// Check message for synack
		if (strcmp(buffer, "SYN") == 0) {
			clients[sockfd].syned = 1;
			clients[sockfd].acked = 0;
			if (ucpSendTo(sockfd, (void *)sendbuf, 7, from) == -1) {
				return -1;
			}
		} else if (strcmp(buffer, "ACK") == 0) {
			// Must send syn first
			if (clients[sockfd].syned == 0) {
				return -1;
			}
			clients[sockfd].acked = 1;
		} else {
			ucpSendTo(sockfd, (void *)ackbuf, 4, from);
		}

		if (clients[sockfd].syned == 1 && clients[sockfd].acked == 1) {
			// Since we done synacking save the client info
			sockets[sockfd].clientIp = ipaddr;
			sockets[sockfd].port = from->sin_port;
			asockfd = ucpSocket();
			initASocket(sockfd, asockfd, ipaddr);
			return asockfd;
		}
	}
	return -1;
}

ssize_t rcsRecv(int asockfd, void *buf, int len) {
	int numrecv;
	char sendbuf[64];

	if (asockets.find(asockfd) == asockets.end()) {	// sockindex should be an asocket
		errno = EBADF;
		return -1;
	}

	struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	
	if ((numrecv = ucpRecvFrom(asockfd, buf, len, from)) == -1) {
		return -1;
	}

	strcpy(sendbuf, "ACK");
	ucpSendTo(asockfd, (void *)sendbuf, 3, from);

	free(from);
	from = NULL;
	return numrecv;
}

int rcsClose(int sockfd)
{
	u_long clientIp;
	int socket;

	if (sockets.find(sockfd) != sockets.end()) {
		sockets.erase(sockets.find(sockfd));
		//clients.erase(clients.find(sockfd));
		return ucpClose(sockfd);
	} else if (asockets.find(sockfd) != asockets.end()) {
		socket = asockets[sockfd].sockfd;
		clientIp = asockets[sockfd].clientIp;
		asockets.erase(asockets.find(sockfd));

		// Remove client from list of connected clients
		clients.erase(clients.find(socket));
		return ucpClose(sockfd);
	} else {
		// Not a proper sockfd
		errno = EBADF;
		return -1;
	}
}

