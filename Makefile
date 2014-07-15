all: librcs.a

rcs.o: rcs.c rcssocket.h ucp_c.c mybind.c
	g++ -pthread rcs.c ucp_c.c mybind.c -o rcs.o

librcs.a: rcs.o mybind.o
	ar rcs librcs.a rcs.o mybind.o

clean:
	rm -rf *.o *.a
