#include <stdlib.h>
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

int init(void) {
    device = NULL;
    readfile = 0;
    memset(&fp, 0, sizeof(fp));
    init_filter(fl);
    return SUCCESS;
}
