#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <stdio.h>
#include <stdlib.h>

#define No_Error 0x00
#define Format_Error 0x01
#define Server_Failure 0x02
#define Name_Error 0x03
#define Not_implemented 0x04
#define Refused 0x05
#define YX_Domain 0x06
#define YX_RR_Set 0x07
#define NX_RR_Set 0x08
#define Not_Auth 0x09
#define Not_Zone 0x10

typedef struct _string {
    int len;
    char *str;
} string;

typedef struct _dnshdr {
    uint16_t id;
    uint16_t qr:1;
    uint16_t opcode:4;
    uint16_t aa:1;
    uint16_t tc:1;
    uint16_t rd:1;

    uint16_t ra:1;
    //uint16_t z:3; // three reserved bits set to zero.
    uint16_t rcode:4;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dnshdr_t;

typedef struct _dnsquery {
    string domain;
    uint16_t qtype;
    uint16_t qclass;
} dnsquery;

#endif
