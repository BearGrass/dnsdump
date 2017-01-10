all:dnsdump

CFLAGS=-g -O0 -Wall
LDFLAGS = -lpcap

dnsdump:dnsdump.o opt.o init.o

dnsdump.o:dnsdump.c dnsdump.h util.h

opt.o: opt.c opt.h util.h

init.o:init.c init.h util.h

.PHONY:clean

clean:
	rm *.o dnsdump
