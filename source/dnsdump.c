#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/stat.h>

#include "dnsdump.h"
#include "init.h"
#include "opt.h"
#include "util.h"

/* global variables */
Filter fl;
char *device = NULL;
int readfile;

int main(int argc, char *argv[]) {
    int ret;
    struct stat st;
    init();
    ret = parse_opt(argc, argv);
    if (ret == ERROR) {
        exit(1);
    }
    argc -= optind; // reduces the argument number by optind
    argv += optind; // changes the pointer to go optind items after the first one

    if (argc > 0) {
        fl.dname = strdup(argv[0]);
    }
    if (device == NULL) {
        device = strdup("any");
    }
    if (stat(device, &st) == 0) {
        readfile = 1;
    }
    if (readfile) {
        // TODO: get offline pcap file
    } else {
        // TODO: get online pcap stream
    }
    return 0;
}
