struct pcap {
    int fd;
    int snapshot;
    int linktype;
    int tzoff;      /* timezone offset */
    int offset;     /* offset for proper alignment */

    struct pcap_sf sf;
    struct pcap_md md;

    /*
     * Read buffer.
     */
    int bufsize;
    u_char *buffer;
    u_char *bp;
    int cc;

    /*
     * Place holder for pcap_next().
     */
    u_char *pkt;


    /*
     * Placeholder for filter code if bpf not in kernel.
     */
    struct bpf_program fcode;

    char errbuf[PCAP_ERRBUF_SIZE];
};

struct ether_header
