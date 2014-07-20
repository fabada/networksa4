#define MAX_DATA_LEN 1000
#define TERM_SEND 12

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
extern unsigned int get_rand();

map<int, rcssocket> sockets;
map<int, asocket> asockets;						// asockfd maps to the sockfd
map<int, client> clients;						// client status

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
	sockets[asockfd].sockfd = sockfd;
	sockets[asockfd].clientIp = ipaddr;
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

void initRcsHeader(rcs_header *header) {
	header->source_port = 0;
	header->dest_port = 0;
	header->seq_num = 0;
	header->ack_num = 0;
	header->offset = 0;
	header->data_len = 0;
	header->checksum = 0;
	header->flags = 0;
}

// Taken from http://www.cse.yorku.ca/~oz/hash.html
unsigned long hash(unsigned char *str, int len)
{
	if (len == 0) return 0;

    unsigned long hash = 5381;
    int c, i;

    for (i = 0; i < len; i++) {
    	c = str[i];
		hash += c;
    }

    return hash;
}

unsigned long compute_header_checksum(rcs_header *header) {
	header->checksum = 0;
	return hash((unsigned char*)header, sizeof(rcs_header));
}

void make_pkt(int seqnum, const void* data, int data_len, unsigned char* sendpkt) {
	rcs_header header;
	initRcsHeader(&header);
	header.seq_num = seqnum;
	header.flags = SYN;

	if (data_len < MAX_DATA_LEN) {
		header.flags = FIN;
	}

	header.offset = seqnum * MAX_DATA_LEN;
	header.data_len = data_len;
	header.checksum = hash((unsigned char*)&header, sizeof(rcs_header)) + hash((unsigned char*)data, data_len);
	memcpy(sendpkt, (void*)&header, sizeof(rcs_header));
	memcpy(sendpkt + sizeof(rcs_header), data, data_len);
}

/**
 * ACK the CLOSE flag from the other end of the connection when it closes
 */
int ackClose(int sockfd, struct sockaddr_in *from, rcs_header *send_header) {
	if (clients.find(sockfd) != clients.end()) {
		clients.erase(clients.find(sockfd));		// Client disconnected
	}
	send_header->checksum = 0;
	send_header->flags = ACK;
	send_header->checksum = hash((unsigned char*)send_header, sizeof(rcs_header));
	if (ucpSendTo(sockfd, (void *)send_header, sizeof(rcs_header), from) == -1) {
		return -1;
	}

	return 0;
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
    sockets[sockfd].ipaddr = addr->sin_addr.s_addr;
    return 0;
}

int rcsListen(int sockfd) {
	// Find the rcsocket associated with the file descriptor
	sockets[sockfd].listening = 1;

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
	unsigned long checksum, h;
	struct sockaddr_in from;
	unsigned int seq_num;
	unsigned int reply_seq_num;
	int done = 0;

	if (sockets.find(sockfd) == sockets.end()) {
		errno = EBADF;
		return -1;
	}
	if (sockets[sockfd].bound == 0) {
		errno = EBADF;
		return -1;
	}

	initRcsHeader(&rcv_header);
	initRcsHeader(&send_header);

	ucpSetSockRecvTimeout(sockfd, 100);

	// First syn, then ack. Use a loop in case of failure
	while (true) {
		done = 0;
		seq_num = get_rand()%100000;
		send_header.flags = SYN;
		send_header.seq_num = seq_num;

		send_header.checksum = compute_header_checksum(&send_header);
		if (ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), server) == -1) {
			return -1;
		}

		if (ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), &from) == -1) {
			continue;
		}
		checksum = rcv_header.checksum;
		h = compute_header_checksum(&rcv_header);
		if (checksum != h) {
			continue;
		}
		if (rcv_header.flags & CLOSE) {	// Connection was closed by the server
			ackClose(sockfd, (struct sockaddr_in *)server, &send_header);
			continue;
		} else if (!((rcv_header.flags & SYNACK) && rcv_header.ack_num == seq_num + 1)) {
			continue;
		}

		reply_seq_num = rcv_header.seq_num;
		send_header.flags = ACK;
		send_header.ack_num = reply_seq_num + 1;

		send_header.checksum = compute_header_checksum(&send_header);
		if (ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), server) == -1) {
			return -1;
		}

		for (int i = 0; i < TERM_SEND; ++i)
		{
			ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), &from);
			checksum = rcv_header.checksum;
			h = compute_header_checksum(&rcv_header);
			if (checksum != h) {
				continue;
			}
			if (rcv_header.flags & CLOSE) {	// Connection was closed by the server
				errno = ENETUNREACH;
				return -1;
			} else if (!(rcv_header.flags & ACK)) {
				continue;
			}
			done = 1;
			sockets[sockfd].serverIp = from.sin_addr.s_addr;
			sockets[sockfd].port = from.sin_port;
			memcpy(&sockets[sockfd].sockaddr, &from, sizeof(struct sockaddr_in));
		}
		if (done == 1) {
			break;
		}
	}

	return 0;
}

int rcsAccept(int sockfd, struct sockaddr_in *from) {
	u_long ipaddr;
	int asockfd;
	rcs_header send_header, rcv_header;
	unsigned long h = 0;
	unsigned long checksum;
	unsigned int seq_num;
	unsigned int reply_seq_num;
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

	initRcsHeader(&send_header);
	initRcsHeader(&rcv_header);
	ucpSetSockRecvTimeout(sockfd, 0);

	while (true) {
		// SYN
		if (ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), from) == -1) {
			continue;
		}
		ucpSetSockRecvTimeout(sockfd, 50);
		ipaddr = from->sin_addr.s_addr;
		clients[sockfd] = initClient(ipaddr);

		checksum = rcv_header.checksum;
		h = compute_header_checksum(&rcv_header);
		if (checksum != h) {
			send_header.flags = ERR;
			send_header.checksum = compute_header_checksum(&send_header);
			ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), from);
			continue;
		}

		// Check message for synack
		if (rcv_header.flags & SYN) {
			seq_num = get_rand() % 100000;
			reply_seq_num = rcv_header.seq_num;
			clients[sockfd].syned = 1;
			clients[sockfd].acked = 0;

			send_header.flags = SYNACK;
			send_header.seq_num = seq_num;
			send_header.ack_num = reply_seq_num + 1;
			send_header.checksum = compute_header_checksum(&send_header);
			if (ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), from) == -1) {
				return -1;
			}
		} else if (rcv_header.flags & CLOSE) {
			ackClose(sockfd, from, &send_header);
			continue;
		} else {
			continue;
		}

		// Get the ACK
		if (ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), from) == -1) {
			continue;
		}

		checksum = rcv_header.checksum;
		h = compute_header_checksum(&rcv_header);
		if (checksum != h) {
			send_header.flags = ERR;
			send_header.checksum = compute_header_checksum(&send_header);
			ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), from);
			continue;
		}

		if (rcv_header.flags & ACK) {
			// Must send syn first
			if (clients[sockfd].syned == 0 || rcv_header.ack_num != seq_num + 1) {
				continue;
			}
			// Setup the asocket, so the cnonecting client can ack to it	
			sockets[sockfd].clientIp = ipaddr;
			sockets[sockfd].port = from->sin_port;
			asockfd = ucpSocket();
			initASocket(sockfd, asockfd, ipaddr);
			memcpy(&sockets[asockfd].sockaddr, from, sizeof(struct sockaddr_in));
			struct sockaddr_in a;

			memset(&a, 0, sizeof(struct sockaddr_in));
			a.sin_family = AF_INET;
			a.sin_port = 0;
			a.sin_addr.s_addr = INADDR_ANY;

			rcsBind(asockfd, &a);

			clients[sockfd].acked = 1;
		} else if (rcv_header.flags & CLOSE) {
			ackClose(sockfd, from, &send_header);
			continue;
		} else {
			continue;
		}


		for (int i = 0; i < TERM_SEND; ++i)
		{
			send_header.flags = ACK;
			send_header.checksum = compute_header_checksum(&send_header);
			ucpSendTo(asockfd, (void *)&send_header, sizeof(rcs_header), from);
		}
		if (clients[sockfd].syned == 1 && clients[sockfd].acked == 1) {
			return asockfd;
		}
	}

	return -1;
}

int rcsRecv(int sockfd, void *buf, int len) {
	unsigned int expectedseqnum = 0;
	unsigned long checksum, header_checksum, body_checksum;
	int numrecv = 0, size = 0;
	rcs_header send_header, rcv_header;
	unsigned char rcvbuf[MAX_DATA_LEN + sizeof(rcs_header)];

	initRcsHeader(&rcv_header);
	initRcsHeader(&send_header);

	for (int i = 0; i < MAX_DATA_LEN + sizeof(rcs_header); i++) {
		rcvbuf[i] = 0;
	}

	struct sockaddr_in from;

	send_header.seq_num = 20;
	send_header.flags = ACK;
	send_header.checksum = compute_header_checksum(&send_header);

	ucpSetSockRecvTimeout(sockfd, 0);
	for(;;) {
		if (size = ucpRecvFrom(sockfd, rcvbuf, MAX_DATA_LEN + 100, &from) == -1) { // Timeout or other error
			ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
		} else {
			ucpSetSockRecvTimeout(sockfd, 200);
			memcpy(&rcv_header, rcvbuf, sizeof(rcs_header));
			checksum = rcv_header.checksum;

			if (rcv_header.data_len > len) {
				ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
				continue;
			}

			header_checksum = compute_header_checksum(&rcv_header);
			body_checksum = hash(&rcvbuf[sizeof(rcs_header)], rcv_header.data_len);

			if (checksum != (compute_header_checksum(&rcv_header) + hash(&rcvbuf[sizeof(rcs_header)], rcv_header.data_len))) {
				ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
				continue;
			}

			if (rcv_header.flags & CLOSE) {
				ackClose(sockfd, &from, &send_header);
				return -1;
			}

			if (rcv_header.seq_num == expectedseqnum) {
				memcpy(&(((unsigned char*)buf)[numrecv]), &(rcvbuf[sizeof(rcs_header)]), rcv_header.data_len);
				numrecv = numrecv + rcv_header.data_len;
				send_header.seq_num = rcv_header.seq_num;
				send_header.checksum = compute_header_checksum(&send_header);
				expectedseqnum++;
			}

			if (rcv_header.flags & FIN) {
				send_header.flags = FIN;
				send_header.checksum = compute_header_checksum(&send_header);
				for (int i = 0; i < TERM_SEND; i++) {
					ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
				}
				break;
			} else {
				ucpSendTo(sockfd, (void*)&send_header, sizeof(rcs_header), &sockets[sockfd].sockaddr);
			}
		}
	}

	return numrecv;
}

int rcsSend(int sockfd, const void* buf, int len) {
	unsigned char sendpkt[MAX_DATA_LEN + sizeof(rcs_header)];
	rcs_header send_header, rcv_header;
	int send_complete = 1, cur_len;
	unsigned int totalseqnum = (len + MAX_DATA_LEN - 1)/MAX_DATA_LEN, nextseqnum = 0;
	unsigned long checksum;
	struct sockaddr_in from;

	initRcsHeader(&send_header);
	initRcsHeader(&rcv_header);

	ucpSetSockRecvTimeout(sockfd, 2000);
	while (totalseqnum > nextseqnum) {
		if (send_complete == 1) {
			cur_len = MAX_DATA_LEN;
			if ((nextseqnum + 1) * MAX_DATA_LEN > (unsigned int)len) {
				cur_len = len - nextseqnum * MAX_DATA_LEN;
			}
			make_pkt(nextseqnum, &(((unsigned char*)buf)[nextseqnum * MAX_DATA_LEN]), cur_len, sendpkt);
			send_complete = 0;
		}
		ucpSendTo(sockfd, sendpkt, cur_len + sizeof(rcs_header), &sockets[sockfd].sockaddr);

		int size = ucpRecvFrom(sockfd, &rcv_header, sizeof(rcs_header), &from);

		if (size == -1) { // Timeout
			continue;
		} else {
			ucpSetSockRecvTimeout(sockfd, 0);
			checksum = rcv_header.checksum;
			if (checksum == compute_header_checksum(&rcv_header)) {
				if (rcv_header.flags & FIN) {
					break;
				} else if (rcv_header.flags & ACK && rcv_header.seq_num == nextseqnum) {
					send_complete = 1;
					nextseqnum++;
				} else if (rcv_header.flags & CLOSE) {
					ackClose(sockfd, &from, &send_header);
					return len;
				} else {
					continue;
				}
			} else {
				continue;
			}
		}
	}

	ucpSetSockRecvTimeout(sockfd, 50);
	for(int i = 0; i < TERM_SEND; i++) {
		ucpRecvFrom(sockfd, &rcv_header, sizeof(rcs_header), &from);
	}

	return len;
}

int rcsClose(int sockfd)
{
	rcs_header send_header, rcv_header;
	struct sockaddr_in from;
	unsigned long checksum;
	int socket;
	int tries = 0;
	struct sockaddr_in peer;
	peer.sin_family = AF_INET;

	initRcsHeader(&rcv_header);
	initRcsHeader(&send_header);
	send_header.flags = CLOSE;
	send_header.checksum = hash((unsigned char*)&send_header, sizeof(rcs_header));
	ucpSetSockRecvTimeout(sockfd, 100);
	if (sockets.find(sockfd) != sockets.end()) {
		socket = sockets[sockfd].sockfd;
		peer.sin_port = sockets[sockfd].port;

		if (sockets[sockfd].serverIp > 0) {
			peer.sin_addr.s_addr = sockets[sockfd].serverIp;
		} else {
			peer.sin_addr.s_addr = sockets[sockfd].clientIp;
			clients.erase(clients.find(socket));
		}
		sockets.erase(sockets.find(sockfd));

		// Inform the peer in the client server link that the connection is closed
		while (peer.sin_addr.s_addr > 0 && tries < 5) {
			tries++;
			ucpSendTo(sockfd, (void *)&send_header, sizeof(rcs_header), &peer);
			// Make sure we get a response from the client acknowledging the socket close
			if (ucpRecvFrom(sockfd, (void *)&rcv_header, sizeof(rcs_header), &from) == -1) {
				continue;
			} else {
				checksum = rcv_header.checksum;
				rcv_header.checksum = 0;
				if (checksum == hash((unsigned char*)&rcv_header, sizeof(rcs_header))
					&& (rcv_header.flags & ACK)) {
					break;
				}
			}
		}

		return ucpClose(sockfd);
	} else {
		// Not a proper sockfdi
		errno = EBADF;
		return -1;
	}
}

