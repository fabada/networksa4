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
	rcs_header send_header, rcv_header;

	if (sockets.find(sockfd) == sockets.end()) {
		errno = EBADF;
		return -1;
	}
	if (sockets[sockfd].bound == 0) {
		errno = EBADF;
		return -1;
	}

	struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));

	send_header.seq_num = 0;
	send_header.offset = 0;
	send_header.data_len = 0;

	// First syn, then ack. Use a loop in case of failure
	while (true) {
		send_header.flags = SYN;
		send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
		if (ucpSendTo(sockfd, (void *)send_header, sizeof(rcs_header), server) == -1) {
			return -1;
		}
		if (ucpRecvFrom(sockfd, (void *)rcv_header, sizeof(rcv_header), from) == -1) {
			return -1;
		}
		if ((rcv_header.flags & SYNACK) == 0) {
			continue;
		}
		send_header.flags = ACK;
		send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
		if (ucpSendTo(sockfd, (void *)send_header, sizeof(rcs_header), server) == -1) {
			return -1;
		}
		break;
	}

	sockets[sockfd].serverIp = server->sin_addr.s_addr;
	sockets[sockfd].port = server->sin_port;

	free(from);
	from = NULL;
	return 0;
}

int rcsAccept(int sockfd, struct sockaddr_in *from) {
	int status;
	u_long ipaddr;
	int asockfd;
	rcs_header send_header, rcv_header;

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

	send_header.seq_num = 0;
	send_header.offset = 0;
	send_header.data_len = 0;

	while ((status = ucpRecvFrom(sockfd, (void *)rcv_header, sizeof(rcs_header), from)) >= 0) {
		if (rcv_header.checksum != hash((unsigned char*)&rcv_header, sizeof(rcs_header))) {
			continue;
		}

		ipaddr = from->sin_addr.s_addr;
		if (clients.find(sockfd) == clients.end()) {
			// New client
			clients[sockfd] = initClient(ipaddr);
		}

		// Check message for synack
		if (rcv_header.flags & SYN) {
			clients[sockfd].syned = 1;
			clients[sockfd].acked = 0;

			send_header.flags = SYNACK;
			send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
			if (ucpSendTo(sockfd, (void *)send_header, sizeof(rcs_header), from) == -1) {
				return -1;
			}
		} else if (rcv_header.flags & ACK) {
			// Must send syn first
			if (clients[sockfd].syned == 0) {
				return -1;
			}
			clients[sockfd].acked = 1;
		} else {
			send_header.flags = ACK;
			send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
			ucpSendTo(sockfd, (void *)send_header, sizeof(rcs_header), from);
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
	rcs_header send_header, rcv_header;
	send_header.seq_num = 0;
	send_header.offset = 0;
	send_header.data_len = 0;
	send_header.flags = FIN;
	send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
	u_long clientIp;
	int socket;
	struct sockaddr_in peer;
	peer.sin_family = AF_INET;

	if (sockets.find(sockfd) != sockets.end()) {
		peer.sin_port = sockets[sockfd].port;

		if (sockets[sockfd].serverIp > 0) {
			peer.sin_addr.s_addr = sockets[sockfd].serverIp;
		} else {
			peer.sin_addr.s_addr = sockets[sockfd].clientIp;
			clients.erase(clients.find(sockfd));
		}
		sockets.erase(sockets.find(sockfd));

		// Inform the peer in the client server link that the connection is closed
		while (1) {
			ucpSendTo(sockfd, (void *)send_header, sizeof(rcs_header), peer);

			// Make sure we get a response from the client acknowledging the socket close
			if (ucpRecvFrom(sockfd, (void *)rcv_header, sizeof(rcs_header), sockets[sockfd].client) == 1) {
				continue;
			} else {
				if (rcv_header.checksum == hash((unsigned char*)&rcv_header, sizeof(rcs_header))
					&& (rcv_header.flags & ACK)) {
					break;
				}
			}
		}

		return ucpClose(sockfd);
	} else if (asockets.find(sockfd) != asockets.end()) {
		socket = asockets[sockfd].sockfd;
		clientIp = asockets[sockfd].clientIp;
		asockets.erase(asockets.find(sockfd));

		// Remove client from list of connected clients
		clients.erase(clients.find(socket));

		peer.sin_addr.s_addr = clientIp;

		// Inform the peer in the client server link that the connection is closed
		while (1) {
			ucpSendTo(sockfd, (void *)send_header, sizeof(rcs_header), peer);

			// Make sure we get a response from the client acknowledging the socket close
			if (ucpRecvFrom(sockfd, (void *)rcv_header, sizeof(rcs_header), sockets[sockfd].client) == 1) {
				continue;
			} else {
				if (rcv_header.checksum == hash((unsigned char*)&rcv_header, sizeof(rcs_header))
					&& (rcv_header.flags & ACK)) {
					break;
				}
			}
		}

		return ucpClose(sockfd);
	} else {
		// Not a proper sockfd
		errno = EBADF;
		return -1;
	}
}
