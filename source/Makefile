all:pcaptest

CFLAGS=-g -O0 -Wall
LDFLAGS = -lpcap

my:pcaptest.o

pcaptest.o:pcaptest.c

.PHONY:clean

clean:
	rm *.o pcaptest
