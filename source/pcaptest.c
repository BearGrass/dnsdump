#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]) {
    //char *dev = argv[1];
    pcap_t *handle;                 /* Session handle */
    char *dev = "bond0";            /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;          /* he compiled filter expression */
    char filter_exp[] = "port 53";  /* The filter expression */
    bpf_u_int32 mask;               /* The netmask of our sniffing device */
    bpf_u_int32 net;                /* The IP of our sniffing device */
//    dev = pcap_lookupdev(errbuf);
//    if (dev == NULL) {
//        fprintf(stderr, "Couldn't find detailedfault device: %s\n", errbuf);
//        return 2;
//    }
    printf("Device: %s\n", dev);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n",dev);
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return 2;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    return 0;
}
