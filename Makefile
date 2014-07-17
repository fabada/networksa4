CFLAGS = -pthread -S -Wall

all: librcs.a

mybind.o:
	gcc $(CFLAGS) mybind.c -o mybind.o

ucp_c.o:
	gcc $(CFLAGS) ucp_c.c -o ucp_c.o

rcs.o: rcs.cc rcssocket.h
	g++ $(CFLAGS) rcs.cc -o rcs.o

librcs.a: rcs.o mybind.o ucp_c.o
	ar rcs librcs.a rcs.o mybind.o ucp_c.o

clean:
	rm -rf *.o *.a
