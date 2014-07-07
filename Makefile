CC = gcc
CFLAGS = -O -Wall -DDEBUG

all: hijack

hijack: hijack.c
	$(CC) $(CFLAGS) -o hijack hijack.c -lnet -lpcap -lbsd

clean:
	rm -f *.o hijack 

