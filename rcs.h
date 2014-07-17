#ifndef A4_RCS_H
#define A4_RCS_H

enum rcs_flags{
	SYN = 1,
	ACK = 2,
	FIN = 4
};

struct rcs_header {
	unsigned int source_port;
	unsigned int dest_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned int offset;
	unsigned int data_len;
	unsigned int checksum;
	unsigned int flags;
};



#endif