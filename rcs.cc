#define MAX_DATA_LEN 1500
#define WINDOW_SIZE 4

#include <iostream>
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


#if 1
#define _DEBUG_
#endif


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
static int rcs_server_sockfd, rcs_client_sockfd;

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
	
	printf("Checksum before send: %lu\n", send_header.checksum);
	
	// First syn, then ack. Use a loop in case of failure
	while (true) {
		printf("SYNING\n");

		send_header.flags = SYN;
		send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
		printf("Checksum after computing: %lu\n", send_header.checksum);
		if (ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), server) == -1) {
			return -1;
		}
		printf("RECEIVING SYNACK\n");

		if (ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcv_header), from) == -1) {
			return -1;
		}
		if ((rcv_header.flags & SYNACK) == 0) {
			printf("NOT SYNACK\n");
			continue;
		}

		printf("ACKING\n");
		send_header.flags = ACK;
		send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
		if (ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), server) == -1) {
			return -1;
		}
		break;
	}

	cout << "Connect finished" << endl;

	sockets[sockfd].serverIp = server->sin_addr.s_addr;
	sockets[sockfd].port = server->sin_port;
	memcpy(&sockets[sockfd].sockaddr, from, sizeof(struct sockaddr_in));

	free(from);
	from = NULL;
	return 0;
}

int rcsAccept(int sockfd, struct sockaddr_in *from) {
	int status;
	u_long ipaddr;
	int asockfd;
	rcs_header send_header, rcv_header;
	unsigned long h;
	unsigned long checksum;
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

	printf("ACCEPTING\n");
	while ((status = ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), from)) >= 0) {
		checksum = rcv_header.checksum;
		rcv_header.checksum = 0;
		if (checksum != (h = hash((unsigned char*)&rcv_header, sizeof(rcs_header)))) {
			printf("CORRUPTED\n");
			printf("Checksum: %lu, Hash: %lu\n", checksum, h);
			send_header.flags = ACK;
			send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
			ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), from);
			continue;
		}

		ipaddr = from->sin_addr.s_addr;
		if (clients.find(sockfd) == clients.end()) {
			// New client
			clients[sockfd] = initClient(ipaddr);
		}

		// Check message for synack
		if (rcv_header.flags & SYN) {
			printf("SYNED\n");

			clients[sockfd].syned = 1;
			clients[sockfd].acked = 0;

			send_header.flags = SYNACK;
			send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
			if (ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), from) == -1) {
				return -1;
			}
		} else if (rcv_header.flags & ACK) {
			printf("ACKED\n");

			// Must send syn first
			if (clients[sockfd].syned == 0) {
				return -1;
			}
			clients[sockfd].acked = 1;
		} else {
			printf("NO RECOGNIZE\n");

			send_header.flags = ACK;
			send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
			ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), from);
		}

		if (clients[sockfd].syned == 1 && clients[sockfd].acked == 1) {
			printf("SYNACKED\n");

			// Since we done synacking save the client info
			sockets[sockfd].clientIp = ipaddr;
			sockets[sockfd].port = from->sin_port;
			memcpy(&sockets[sockfd].sockaddr, from, sizeof(struct sockaddr_in));

			asockfd = ucpSocket();
			initASocket(sockfd, asockfd, ipaddr);
			return asockfd;
		}
	}

	cout << "Accept finished" << endl;
	return -1;
}

int rcsRecv(int sockfd, void *buf, int len) {
	unsigned int expectedseqnum = 0;
	int numrecv = 0;
	rcs_header send_header, rcv_header;
	unsigned char rcvbuf[1600];

	struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));

	send_header.seq_num = 20;
	send_header.flags = ACK;

	send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));

	for(;;) {
		if (ucpRecvFrom(rcs_server_sockfd, rcvbuf, MAX_DATA_LEN + 100, from) == -1) { // Timeout or other error
			ucpSendTo(rcs_server_sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
		} else {
			memcpy(&rcv_header, rcvbuf, sizeof(rcs_header));
			if (rcv_header.data_len < 0 || rcv_header.data_len <= MAX_DATA_LEN) { // Corrupted
				ucpSendTo(rcs_server_sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
			} else if (rcv_header.checksum == (hash((unsigned char*)&rcv_header, sizeof(rcs_header)) + hash(&rcvbuf[sizeof(rcs_header)], rcv_header.data_len))
					&& rcv_header.seq_num == expectedseqnum) {
		//		memcpy(&buf[numrecv], &rcvbuf[sizeof(rcs_header)], rcv_header.data_len);
				numrecv = numrecv + rcv_header.data_len;
				send_header.seq_num = rcv_header.seq_num;
				expectedseqnum++;
				send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
				ucpSendTo(rcs_server_sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
			} else {
				ucpSendTo(rcs_server_sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
			}
		}
	}
	free(from);
	return numrecv;
}

int rcsSend(int sockfd, const void* buf, int len) {
	unsigned char sendpkt[MAX_DATA_LEN + 100];
	rcs_header rcv_header;
	int i, send_complete = 1, cur_len;
	unsigned int totalseqnum = (len + MAX_DATA_LEN - 1)/MAX_DATA_LEN, nextseqnum = 0;

	struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));

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
//			make_pkt(nextseqnum, &buf[nextseqnum * MAX_DATA_LEN], cur_len, sendpkt);
			send_complete = 0;
		}
		ucpSendTo(rcs_client_sockfd, sendpkt, cur_len + sizeof(rcs_header), &sockets[sockfd].sockaddr);

		int size = ucpRecvFrom(rcs_client_sockfd, &rcv_header, 100, from);

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

	free(from);
	return len;

}

int rcsClose(int sockfd)
{
	rcs_header send_header, rcv_header;
	send_header.seq_num = 0;
	send_header.offset = 0;
	send_header.data_len = 0;
	send_header.flags = FIN;
	send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
	struct sockaddr_in from;
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
			ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), &peer);

			// Make sure we get a response from the client acknowledging the socket close
			if (ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), &from) == 1) {
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
			ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), &peer);

			// Make sure we get a response from the client acknowledging the socket close
			if (ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), &from) == 1) {
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

