#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/if_ether.h>

#include "dnsdump.h"
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
