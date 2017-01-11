#ifndef __OPT_H__
#define __OPT_H__

#include <getopt.h>
#include <stdio.h>

static const char short_options[] = "hi:p:";
static const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"interface", 0, NULL, 'i'},
    {"port", 0, NULL, 'p'},
};

void usage(void);
int parse_opt(int argc, char *argv[]);

#endif
