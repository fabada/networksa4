#ifndef A4_RCS_H
#define A4_RCS_H

typedef enum [
	SYN = 1,
	ACK = 2,
	FIN = 4
] rcs_flags;

typedef struct {
	unsigned int source_port;
	unsigned int dest_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned int offset;
	unsigned int checksum;
	unsigned int flags;
} rcs_header;



#endif