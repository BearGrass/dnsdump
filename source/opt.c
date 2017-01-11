#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "opt.h"
#include "util.h"
#include "dnsdump.h"

extern char *device;
extern Filter fl;


void usage(void) {
    printf("DNSDump is a tool based on libpcap, which dump DNS packages "
            "with users filter.\n"
            "Usage: dnsdump <command> [options] \n\n"
            "Commands:\n"
            "    -i --device    set the device to be sniffed\n"
            "    -h --help      display the help messages\n"
            );
}

int parse_opt(int argc, char *argv[]) {
    int ret, L;
    while ((ret = getopt_long(argc, argv, short_options, long_options,
                    NULL)) != ERROR) {
        switch (ret) {
            case 'h':
                usage();
                break;
            case 'i':
                device = strdup(optarg);
                break;
            case 'p':
                fl.port = atoi(optarg);
                break;
            default:
                usage();
                return ERROR;
        }
    }
    return SUCCESS;
}
