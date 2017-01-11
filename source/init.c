#include <stdlib.h>

#include "init.h"
#include "util.h"
#include "dnsdump.h"

extern char *device;
extern Filter fl;
extern int readfile;

static int init_filter(Filter fl) {
    fl.dname = NULL;
    fl.port = 53;
    return SUCCESS;
}

int init(void) {
    device = NULL;
    readfile = 0;
    init_filter(fl);
    return SUCCESS;
}
