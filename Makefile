CFLAGS = -pthread -Wall

all: rcsapp

mybind.o:
	gcc $(CFLAGS) mybind.c -o mybind.o

ucp_c.o:
	gcc $(CFLAGS) ucp_c.c -o ucp_c.o

rcs.o: rcs.cc rcssocket.h mybind.o ucp_c.o
	g++ $(CFLAGS) rcs.cc -o rcs.o mybind.o ucp_c.o

librcs.a: rcs.o mybind.o ucp_c.o
	ar rcs librcs.a rcs.o mybind.o ucp_c.o

rcsapp:
	g++ $(CFLAGS) rcsapp-client.c mybind.c ucp_c.c rcs.cc -o rcsapp-client
	g++ $(CFLAGS) rcsapp-server.c mybind.c ucp_c.c rcs.cc -o rcsapp-server

clean:
	rm -rf *.o *.a rcsapp-client rcsapp-server
