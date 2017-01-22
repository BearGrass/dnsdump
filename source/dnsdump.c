#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <pcap.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
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
static Pacinfo pac;

void get_ip(char ip[], struct in_addr nip) {
    strcpy(ip, inet_ntoa(nip));
}

void handle_pcap(u_char * udata, const struct pcap_pkthdr *hdr,
        const u_char * pkt) {
    /* judge the length of ETH header */
    if (hdr->caplen < ETHER_HDR_LEN)
        return;
    if (handle_datalink(pkt, hdr->caplen) == 0) {
        return;
    }
    time(&pac.ts);
//    last_ts = hdr->ts;
}

int handle_linux_sll(const u_char *pkt, int len) {
    /* Skip the extra 2 byte field inserted in "Linux Cooked" captures.
     * if dev is any datalink will have 2 bytes.
     * if use eth0 or other, datalink will not.
     */
    sll_header_t *sllhdr = (void*)pkt;
    unsigned short eth_type = ntohs(sllhdr->proto_type);
    if (len < SLL_HDR_LEN) {
        return 0;
    }
    pkt += SLL_HDR_LEN;
    len -= SLL_HDR_LEN;
    handle_ip(pkt, len, eth_type);
}

int handle_eth(const u_char *pkt, int len) {
    struct ether_header *eth_hdr = (void *)pkt;
    unsigned short eth_type = ntohs(eth_hdr->ether_type);
    if (len < ETHER_HDR_LEN) {
        return 0;
    }
    pkt += ETHER_HDR_LEN;
    len -= ETHER_HDR_LEN;
    if ( eth_type = ETHERTYPE_8021Q) {
        /* VLAN environment */
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
    return handle_udp((struct udphdr*)((char *)iph + offset), len - offset, &sip, &dip);
}

int handle_udp(const struct udphdr* uh, int len,
        struct in_addr *sip,
        struct in_addr *dip) {
    int off = sizeof(uh);
    if (uh->uh_dport != ntohs(53)) {
        return 0;
    }
    return handle_dns((char*)uh + off, len - off, sip, dip);
}

int handle_dns(const char *buf, int len,
        struct in_addr *sip,
        struct in_addr *dip) {
    dnshdr_t dnshdr;
    const char *dnspos = buf;
    dnsquery_t qr;
    uint16_t tmp;
    char query[256];
    int offset, query_len;
    int ret;
    pac.paclen = 1;
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
    if (dnshdr.qdcount != 1) {
        pr_func("Not support multiple query\n");
        return -1;
    }

    memcpy(&tmp, buf+6, 2);
    dnshdr.ancount = ntohs(tmp);

    memcpy(&tmp, buf+8, 2);
    dnshdr.nscount = ntohs(tmp);

    memcpy(&tmp, buf+10, 2);
    dnshdr.arcount = ntohs(tmp);

    dnspos += 12;
    ret = get_domain(buf, dnspos, &offset, query, &query_len);
    dnspos += offset;
    qr.domain.str = query;
    qr.domain.len = query_len;
    memcpy(&qr.qtype, dnspos, 2);
    memcpy(&qr.qclass, dnspos + 2, 2);
    dnspos += 4;

    get_ip(pac.sip, *sip);
    get_ip(pac.dip, *dip);
    pac.dname.str = (char*)malloc(query_len);
    pac.dname.len = query_len;
    memcpy(pac.dname.str , query, query_len);
    pac.paclen = 1;
    show();
    return 0;
}

inline int is_pointer(char x) {
    return ((x & 0xc0) == 0xc0);
}

int get_domain(const char *buf, const char *pos, int *offset, char domain[], int *len) {
    const char *p = pos;
    char pdomain[256]; // domain indicated by program, maybe need
    char data;
    int plen, i, end = 0;
    *offset = 0;
    *len = plen = 0;
//    for (i = 0; i < 20; i ++) {
//        printf("%02x ", p[i]);
//    }
//    puts("");
    while (p != NULL && *p != 0) {
        data = *p;
        if (is_pointer(data)) {
            p = buf + *(p+1) + ((data & 0x3f) << 8);
            end = (end == 0)?*offset + 2:end;  // 0x0cc0 2 bytes
        } else {
            pdomain[plen ++] = data;
            p ++;
            for (i = 0; i < data; i ++, p ++) {
                if (p == NULL || (!isalnum(*p) && *p != '-')) {
                    // the datagram is illegal,maybe short? ^ ^
                    return -1;
                }
                pdomain[plen ++] = *p;
                domain[(*len)++] = *p;
            }
            domain[(*len)++] = '.';
            *offset += data + 1;
        }
    }
    // If domain contains 0xc0,then offset calcuate would be fixed after jump to new point
    *offset = (end == 0)?*offset:end;
    return 0;
}

void show(void) {
    struct tm *tp;
    tp = localtime(&pac.ts);
    printf("%02d-%02d-%d ",
            (1 + tp->tm_mon), tp->tm_mday, (1900 + tp->tm_year));
    printf("%02d:%02d:%02d ",
            tp->tm_hour, tp->tm_min, tp->tm_sec);
    pr_func("%s -> %s %s\n",pac.sip, pac.dip,pac.dname.str);
    init_pac(pac);
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
        case DLT_LINUX_SLL:
            handle_datalink = handle_linux_sll;
            break;
        default:
            fprintf(stderr, "unsupported data link type %d\n", ret);
            exit(1);
            break;
    }
    init_pac(pac);
    pcap_loop(pcap, -1, handle_pcap, NULL);

    return 0;
}
