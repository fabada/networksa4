CFLAGS = -pthread -Wall

all: librcs.a

rcs.o: rcs.cc rcssocket.h ucp_c.c mybind.c
	g++ $(CFLAGS) rcs.cc ucp_c.c mybind.c -o rcs.o

librcs.a: rcs.o
	ar rcs librcs.a rcs.o

clean:
	rm -rf *.o *.a
