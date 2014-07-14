all: mybind.c tcp-server.c tcp-client.c
	gcc -pthread mybind.c tcp-server.c -o ts
	gcc tcp-client.c -o tc

clean:
	rm -rf a.out *.o ts tc core
