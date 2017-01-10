#ifndef __OPT_H__
#define __OPT_H__

#include <getopt.h>
#include <stdio.h>

extern char *device;

static const char short_options[] = "hi:";
static const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
};

void usage(void);
int parse_opt(int argc, char *argv[]);

#endif
