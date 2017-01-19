#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <string.h>

#include "init.h"
#include "util.h"
#include "dnsdump.h"

extern char *device;
extern Filter fl;
extern int readfile;
extern struct bpf_program fp;

static int init_filter(Filter fl) {
    fl.dname = NULL;
    fl.port = 53;
    return SUCCESS;
}

void init_pac(Pacinfo pac) {
    // TODO: ts initialize to current time
    pac.ts = 0;
    memset(pac.sip, 0, 4);
    memset(pac.dip, 0, 4);
    pac.sport = 0;
    pac.dport = 0;
    pac.dname.len = 0;
    pac.dname.str = NULL;
    pac.paclen = 0;
}

int init(void) {
    device = NULL;
    readfile = 0;
    memset(&fp, 0, sizeof(fp));
    init_filter(fl);
    return SUCCESS;
}
