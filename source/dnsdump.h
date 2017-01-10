#ifndef __DNSDUMP_H__
#define __DNSDUMP_H__

#include <stdint.h>

/*
 * Create at 19:07 1.9 2017 BearGrass
 * email: superlong100@gmail.com
 */

typedef struct string_t {
    int len;
    char *str;
}String;

typedef struct pacinfo_t {
    time_t ts;
    /* The range of ip is (0, 65535) */
    uint32_t sip;
    uint32_t dip;
    /* The range of port is (0, 65535) */
    uint32_t sport;
    uint32_t dport;
    /* DNS query domain name */
    String dname;
    /* length of package */
    int paclen;
}Pacinfo;

#endif
