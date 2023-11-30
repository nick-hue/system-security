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
                pcap_name = strdup(optarg);
                break;  
            case 'f':
                filter = strdup(optarg);
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
            // online mode i think 
            char errbuf[PCAP_ERRBUF_SIZE];
            char *dev = input;
            printf("device: %s\n", dev);

            pcap_t *handle;
            struct bpf_program fp;	
            bpf_u_int32 mask;		/* The netmask of our sniffing device */
            bpf_u_int32 net;		/* The IP of our sniffing device */


            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Can't get netmask for device %s\n", dev);
                net = 0;
                mask = 0;
            }

            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
            }

            if (filter){ // if filter exists apply it, if not dont ¯\_(ツ)_/¯
                printf("filter exists\nfilter : %s\n", filter);

                if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
                    return(2);
                }
                
                if (pcap_setfilter(handle, &fp) == -1) {
                    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
                    return(2);
                }
                //packet = pcap_next(handle, &header);

            } else {
                printf("filter does not exist\n");
            }

            printf("Listening...\n");

            pcap_loop(handle, 5, got_packet, NULL);
            /* Print its length */
            //printf("Jacked a packet with length of [%d]\n", header.len);
            /* And close the session */

            
            pcap_close(handle);

            break;
        case PACKET:
            // offline mode i think
            /*
            char errbuf[PCAP_ERRBUF_SIZE]= {0};
            pcap_t *test = pcap_open_offline(pcap_name, errbuf);

            printf("buffer : %s\n", errbuf);
            */
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
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const unsigned char *packet;		

    /* ethernet headers are always exactly 14 bytes */
    #define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

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
    printf("payload of the packet : %s\n", payload);

}