all:dnsdump

CFLAGS=-g -O0 -Wall
LDFLAGS = -lpcap

dnsdump:dnsdump.o init.o

dnsdump.o:dnsdump.c dnsdump.h util.h

init.o:init.c init.h util.h

.PHONY:clean

clean:
	rm *.o dnsdump
