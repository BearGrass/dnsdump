#ifndef __DNSDUMP_H__
#define __DNSDUMP_H__

#include <stdint.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

/*
 * Create at 19:07 1.9 2017 BearGrass
 * email: superlong100@gmail.com
 */

/*
 * In IEEE 802.3u both the source and destination addresses
 * are 48-bit MAC addresses.
 */
#ifndef ETHER_HDR_LEN
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#endif

/*
 * IEEE 802.1q protocol for "Virtual Bridged Local Area Networks",
 * which is referred to as VLAN.
 * 802.1q header is:
 * SADDR:6, DADDR:6, TPID:2(0X8100) TCI:2 TYPE:2
 */
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x8100
#endif

/*
 * looking at /usr/include/netinet/udp.h
 * if define __FAVOR_BSD we use uh_dport and uh_sport
 * else use dest and source
 */
#if defined(__linux__) || defined(__GLIBC__) || defined(__GNU__)
#define uh_dport dest
#define uh_sport source
#endif

#define PCAP_SNAPLEN 65535

typedef int (printer) (const char *,...);
typedef int (datalink) (const u_char *pkt, int len);

typedef struct string_t {
    int len;
    char *str;
}String;

typedef struct filter_t {
    int port;
    char *dname;
}Filter;

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

void
handle_pcap(u_char * udata, const struct pcap_pkthdr *hdr, const u_char * pkt);

int handle_eth(const u_char *pkt, int len);
int handle_ip(const u_char *pkt, int len, unsigned short type);
int handle_ipv4(const struct ip *iph, int len);
int handle_udp(const struct udphdr* uh, int len,
        struct in_addr *sip, struct in_addr *dip);
int handle_dns(const char *buf, int len,
        struct in_addr *sip, struct in_addr *dip);

void show(void);

#endif
