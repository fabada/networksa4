#define MAX_DATA_LEN 1500
#define WINDOW_SIZE 4

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
#include "rcs.h"

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

// Taken from http://www.cse.yorku.ca/~oz/hash.html
unsigned long hash(unsigned char *str, int len)
{
	if (len == 0) return 0;

    unsigned long hash = 5381;
    int c, i;

    for (i = 0; i < len; i++) {
    	c = str[len];
    	hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

void make_pkt(int seqnum, const void* data, int data_len, unsigned char* sendpkt) {
	rcs_header header;
	header.seq_num = seqnum;
	header.flags = SYN;

	if (data_len < MAX_DATA_LEN) {
		header.flags = header.flags | FIN;
	}

	header.offset = seqnum * MAX_DATA_LEN;
	header.data_len = data_len;
	header.checksum = hash((unsigned char*)&header, sizeof(rcs_header)) + hash((unsigned char*)data, data_len);
	memcpy(sendpkt, (void*)&header, sizeof(rcs_header));
	memcpy(sendpkt + sizeof(rcs_header), data, data_len);
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
			sockets[sockfd].clientIp = ipaddr;
			asockfd = ucpSocket();
			sockets[sockfd].client = asockfd;
			initASocket(sockfd, asockfd, ipaddr);
			return asockfd;
		}
	}
	return -1;
}

int rcsRecv(int sockfd, void *buf, int len) {
	int expectedseqnum = 0;
	int numrecv = 0;
	rcs_header send_header, rcv_header;
	u_long ipaddr;
	unsigned char rcvbuf[1600];

	struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));

	send_header.seq_num = 20;
	send_header.flags = ACK;

	send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));

	for(;;) {
		if (ucpRecvFrom(sockfd, rcvbuf, MAX_DATA_LEN + 100, from) == -1) { // Timeout or other error
			ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), from);
		} else {
			memcpy(&rcv_header, rcvbuf, sizeof(rcs_header));
			if (rcv_header.data_len < 0 || rcv_header.data_len <= MAX_DATA_LEN) { // Corrupted
				ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), from);
			}
			if (rcv_header.checksum == (hash((unsigned char*)&rcv_header, sizeof(rcs_header)) + hash(&rcvbuf[sizeof(rcs_header)], rcv_header.data_len))
					&& rcv_header.seq_num == expectedseqnum) {
				memcpy(&buf[numrecv], &rcvbuf[sizeof(rcs_header)], rcv_header.data_len);
				numrecv = numrecv + rcv_header.data_len;
				send_header.seq_num = rcv_header.seq_num;
				expectedseqnum++;
				send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
				ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), from);
			} else {
				ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), from);
			}
		}
	}
	free(from);
	return numrecv;
}

int rcsSend(int sockfd, const void* buf, int len) {
	unsigned char sendpkt[MAX_DATA_LEN + 100];
	rcs_header rcv_header;
	rcs_header header;
	int i, send_complete = 1, totalseqnum = (len + MAX_DATA_LEN - 1)/MAX_DATA_LEN, cur_len;
	unsigned int nextseqnum = 0;


	if (sockets[i].sockfd != sockfd) {
		return -1;
	}

	ucpSetSockRecvTimeout(sockfd, 100);

	while (totalseqnum > nextseqnum) {
		if (send_complete == 1) {
			cur_len = nextseqnum * MAX_DATA_LEN - len;
			if (cur_len < 0) {
				cur_len = MAX_DATA_LEN;
			}
			make_pkt(nextseqnum, &buf[nextseqnum * MAX_DATA_LEN], cur_len, sendpkt);
			send_complete = 0;
		}
		ucpSendTo(sockfd, sendpkt, cur_len + sizeof(rcs_header), sockets[sockfd].client);

		int size = ucpRecvFrom(sockfd, &rcv_header, 100, sockets[sockfd].client);

		if (size == -1) { // Timeout
			continue;
		} else {
			if (rcv_header.checksum == hash((unsigned char*)&rcv_header, sizeof(rcs_header))) {
				if (rcv_header.flags & ACK && rcv_header.seq_num == nextseqnum) {
					send_complete = 1;
					nextseqnum++;
				} else {
					continue;
				}
			} else {
				continue;
			}
		}
	}

	return len;

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

