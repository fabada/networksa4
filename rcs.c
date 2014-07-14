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

extern int errno;

rcssocket sockets[1000];		// Socket info
int asockets[3000];				// Accepted sockets
static int inited = 0;
static int nextFreeSocket;
static int nextFreeASocket;		// ASocket = accept socket

void init() {
	int i;
	for (i = 0; i < 1000; i++) {
		sockets[i].sockfd = -1;
		sockets[i].hasConnectionRequest = 0;
		sockets[i].hasSocketData = 0;
		sockets[i].listening = 0;
	}
	for (i = 0; i < 3000; i++) {
		asockets[i] = -1;
	}
	inited = 1;
	nextFreeSocket = 0;
	nextFreeASocket = 0;
}

void resetSocket(int sockindex) {
	sockets[sockindex].sockfd = -1;
	sockets[sockindex].hasConnectionRequest = 0;
	sockets[sockindex].hasSocketData = 0;
	sockets[sockindex].listening = 0;
}

int findNextFreeSocket() {
	int i;
	for (i = 0; i < 1000; i++) {
		if (sockets[i].sockfd == -1)
		{
			return i;
		}
	}

	// No free sockets
	return -1;
}

int findNextFreeASocket() {
	int i;
	for (i = 0; i < 3000; i++) {
		if (asockets[i] == -1)
		{
			return i;
		}
	}

	// No free sockets
	return -1;
}

int rcsSocket()
{
	if (nextFreeSocket == -1) {
		errno = ENOBUFS;
		return -1; // No sockets available
	}
	if (inited == 0) {
		init();
	}
	int sockfd = ucpSocket();
	int sockindex = nextFreeSocket;

	sockets[sockindex].sockfd = sockfd;
	nextFreeSocket = findNextFreeSocket();
	return sockindex;
}

int rcsGetSockName(int sockindex, struct sockaddr_in *addr)
{
	if (sockindex > 1000 || sockindex < 0) {
		errno = EBADF;
		return -1;
	}
	int sockfd = sockets[sockindex].sockfd;
	return ucpGetSockName(sockfd, addr);
}

int rcsAccept(int sockindex, struct sockaddr_in *addr) {
	if (nextFreeASocket == -1) {
		errno = ENOBUFS;
		return -1; // No sockets available
	}
	rcssocket *socket = &sockets[sockindex];
	while (socket->hasConnectionRequest == 0);	// "block" if no connection request
	int acceptsockindex = findNextFreeASocket();

	return acceptsockindex + 1000; // > 1000 means the sockfd refers to an accepted socket
}

ssize_t rcsRecv(int sockindex, void *buf, int len) {
	int status;
	int sockfd;
	if (sockindex < 0 || sockindex > 4000) {
		errno = EBADF;
		return -1;
	} else if (sockindex >= 1000) {
		sock fd 
	} else { // sockindex is [0, 1000)
		sockfd = sockets[sockindex].sockfd;
	}

	int sockindex = asockets[asockindex - 1000];
	int sockfd = sockets[sockindex].sockfd;
	struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	
	if (status = ucpRecvFrom(sockfd, buf, len, from) == -1) {
		return -1;
	}

	// Now that we filled out who sent to us inside of from, maintain it in the list


}

int rcsClose(int sockindex)
{
	if (sockindex >= 0 && sockindex < 1000) {
		int sockfd = sockets[sockindex].sockfd;
		resetSocket(sockindex);
		return ucpClose(sockfd);
	} else if (sockindex >= 1000 && sockindex < 4000) {
		// We assign #s 1000 and over to be accepted sockets
		int asockindex = sockindex - 1000;

		// if the asockfd is not open, return -1
		if (asockets[asockindex] == -1) {
			errno = EBADF;
			return -1;
		}
		asockets[asockindex] = -1;
		return 0;
	} else {
		// Not a proper sockfd
		errno = EBADF;
		return -1;
	}
}

int main(int argc, char const *argv[])
{
	init();

	return 0;
}