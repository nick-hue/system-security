#include "pcap_ex.h"

int main(int argc, char *argv[]) {
    int opt;
    char *input = NULL, *pcap_name = NULL, *filter = NULL;
    Mode mode;

    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                mode = INTERFACE;
                input = optarg;
                break;
            case 'r':
                mode = PACKET;
                pcap_name = optarg;
                break;  
            case 'f':
                filter = optarg;
                break;  
            case 'h':
                mode = HELP;
                break;
            default:
                mode = EXIT_MODE;
                fprintf(stderr, "Error invalid arguments given.\nUse -h flag to show more info about arguments.\n");
                exit(1);
        }
    }

    // checking if the user gave no arguments
    if (optind < 2) {
        fprintf(stderr, "Error: No arguments provided.\nUse -h flag to show more info about arguments.\n");
        exit(1);
    }

    switch(mode){
        case INTERFACE:
            // online mode
            break;
        case PACKET:
            // offline mode i think

            pcap_t *handle;			            /* Session handle */
            char errbuf[PCAP_ERRBUF_SIZE];	    /* Error string */
            char *dev;                          /* Device Name */

            //dev = argv[2];
            //printf("Device : %s\n", dev);

            handle = pcap_open_offline(pcap_name, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open pcap file %s: %s\n", dev, errbuf);
                return 2;
            }

            if (pcap_loop(handle, 0, got_packet, NULL) < 0) {
                fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
                return 3;
            }

            pcap_close(handle);
            break;
        case HELP:
            printf("-i Select the network interface name (e.g., eth0)\n-r Packet capture file name (e.g., test.pcap)\n-f Filter expression in string format (e.g., port 8080)\n-h Help message, which show the usage of each parameter\n");                
            break;
        case EXIT_MODE:
            fprintf(stderr, "Error: while getting mode.\nUse -h flag to show more info about arguments.\n");
            exit(EXIT_FAILURE);
    }

    //printf("interface : %s\nfilter : %s\n", input, filter);

    return 0;
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    printf("Calling back...\n");	

    /* ethernet headers are always exactly 14 bytes */
    #define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet;  /* The ethernet header */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    unsigned int size_ip;
    unsigned int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    //printf("payload of the packet : %s\n", payload);

}