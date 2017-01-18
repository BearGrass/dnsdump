#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "dnsdump.h"
#include "protocal.h"
#include "init.h"
#include "opt.h"
#include "util.h"


/* global variables */
Filter fl;
char *device = NULL;
pcap_t *pcap = NULL;
int readfile;
char errbuf[255] = "";
struct bpf_program fp;

//#ifdef HAVE_STRUCT_BPF_TIMEVAL
//struct bpf_timeval last_ts;
//#else
//struct timeval last_ts;
//#endif

/* static variables */
static printer *pr_func = (printer *) printf;
static datalink *handle_datalink = NULL;
static char bpf_program_buf[] = "udp port 53";

void handle_pcap(u_char * udata, const struct pcap_pkthdr *hdr,
        const u_char * pkt) {
    /* judge the length of ETH header */
    if (hdr->caplen < ETHER_HDR_LEN)
        return;
    if (handle_datalink(pkt, hdr->caplen) == 0) {
        return;
    }
//    last_ts = hdr->ts;
}

int handle_eth(const u_char *pkt, int len) {
    struct ether_header *eth_hdr = (void *)pkt;
    unsigned short eth_type = ntohs(eth_hdr->ether_type);
    if (len < ETHER_HDR_LEN) {
        return 0;
    }
    pkt += ETHER_HDR_LEN;
    len -= ETHER_HDR_LEN;
    /* VLAN environment */
    if ( eth_type = ETHERTYPE_8021Q) {
        eth_type = ntohs(*(unsigned short *)(pkt + 2));
        pkt += 4;
        len -= 4;
    }
    return handle_ip(pkt, len, eth_type);
}

int handle_ip(const u_char *pkt, int len, unsigned short type) {
    if (type == ETHERTYPE_IP) {
        /* ETHERTYPE_IP in <netinet/if_ether.h> */
        return handle_ipv4((struct ip*)pkt, len);
    }
    /* TODO: ipv6 */
    return 0;
}

int handle_ipv4(const struct ip *iph, int len) {
    struct in_addr sip;
    struct in_addr dip;
    /* ip_hl store the length of the IP header in 32 bit words(4 bytes). */
    int offset = iph->ip_hl << 2;
    if (offset < 20) {
        /*
         * The minimum value of a correct header is 5
         * which don't have any options.
         */
        return 0;
    }
    memcpy(&sip, &iph->ip_src, sizeof(struct in_addr));
    memcpy(&dip, &iph->ip_dst, sizeof(struct in_addr));
    if (iph->ip_p != IPPROTO_UDP) {
        return 0;
    }
    return handle_udp((struct udphdr*)iph + offset, len - offset, &sip, &dip);
}

int handle_udp(const struct udphdr* uh, int len,
        struct in_addr *sip,
        struct in_addr *dip) {
    int off = sizeof(uh);
    if (uh->uh_dport != ntohl(53)) {
        return 0;
    }
    return handle_dns((char*)uh + off, len - off, sip, dip);
}

int handle_dns(const char *buf, int len,
        struct in_addr *sip,
        struct in_addr *dip) {
    dnshdr_t dnshdr;
    const char *pos = buf;
    uint16_t tmp;
    char query[256];
    int offset, query_len;
    int ret;
    memcpy(&tmp, buf, 2);
    dnshdr.id = ntohs(tmp);
    memcpy(&tmp, buf+2, 2);
    tmp = ntohs(tmp);

    dnshdr.qr = (tmp>>15)&0x01;
    dnshdr.opcode = (tmp>>11)&0x0F;
    dnshdr.aa = (tmp>>10)&0x01;
    dnshdr.tc = (tmp>>9)&0x01;
    dnshdr.rd = (tmp>>8)&0x01;
    dnshdr.ra = (tmp>>7)&0x01;
    dnshdr.rcode = tmp&0x0F;

    memcpy(&tmp, buf+4, 2);
    dnshdr.qdcount = ntohs(tmp);

    memcpy(&tmp, buf+6, 2);
    dnshdr.ancount = ntohs(tmp);

    memcpy(&tmp, buf+8, 2);
    dnshdr.nscount = ntohs(tmp);

    memcpy(&tmp, buf+10, 2);
    dnshdr.arcount = ntohs(tmp);

    pos += 12;
    ret = get_domain(pos, &offset, dnshdr.qdcount, query, &query_len);

    return 0;
}

int get_domain(const char *buf, int *offset, int count, char domain[], int *len) {
    const char *p = buf;
    int i;
    dnsquery *qr;
    qr = (dnsquery*)malloc(sizeof(dnsquery)*count);
    if (qr == NULL) {
        fprintf(stderr, "alloc memory of query error:%s\n", errbuf);
        return -1;
    }
    for (i = 0; i < count; i ++) {
    }
    return 0;
}

void show(void) {
}

int main(int argc, char *argv[]) {
    struct stat st;
    int promisc_flag = 1; // start promiscuous mode
    int ret;
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
        pcap_open_offline(device, errbuf);
    } else {
        pcap = pcap_open_live(device, PCAP_SNAPLEN, promisc_flag, 1, errbuf);
    }
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_*: %s\n", errbuf);
        exit(1);
    }
    ret = pcap_compile(pcap, &fp, bpf_program_buf, 1, 0);
    ret = pcap_setfilter(pcap, &fp);

    ret = pcap_datalink(pcap);
    switch (ret) {
        case DLT_EN10MB:
            handle_datalink = handle_eth;
            break;
        default:
            fprintf(stderr, "unsupported data link type %d\n", ret);
            exit(1);
            break;
    }
    while (1) {
        pcap_dispatch(pcap, 1, handle_pcap, NULL);
        show();
        break;
    }

    return 0;
}
