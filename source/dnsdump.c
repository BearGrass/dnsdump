#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "dnsdump.h"
#include "init.h"
#include "opt.h"
#include "util.h"

int main(int argc, char *argv[]) {
    int ret;
    init();
    ret = parse_opt(argc, argv);
    if (ret == ERROR) {
        exit(1);
    }
    return 0;
}
