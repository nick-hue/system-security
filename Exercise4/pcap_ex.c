#include "pcap_ex.h"

unsigned int total_number_of_packets = 0;   /* Total number of packets received */
unsigned int tcp_packets = 0;               /* Total number of TCP packets received. */
unsigned int udp_packets = 0;               /* Total number of UDP packets received. */
unsigned int tcp_packets_bytes = 0;         /* Total bytes of TCP packets received. */
unsigned int udp_packets_bytes = 0;         /* Total bytes of UDP packets received. */

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
            struct bpf_program fp;		/* The compiled filter */
            //bpf_u_int32 mask;		      /* Our netmask */
            bpf_u_int32 net;		/* Our IP */
            struct pcap_pkthdr header;	/* The header that pcap gives us */
            const unsigned char *packet;		/* The actual packet */

            handle = pcap_open_offline(pcap_name, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open pcap file %s: %s\n", pcap_name, errbuf);
                return 2;
            }

            // if filter exists apply it, if not dont ¯\_(ツ)_/¯
            if (filter){ 
                printf("filter exists\nfilter : %s\n", filter);

                if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
                    return 2;
                }
                
                if (pcap_setfilter(handle, &fp) == -1) {
                    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
                    return 2;
                }
            } else {
                printf("filter does not exist\n");
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

    show_statistics();
    
    return 0;
}

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    printf("\nGot packet...\n");	
    total_number_of_packets++;

    /* ethernet headers are always exactly 14 bytes */
    #define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet;  /* The ethernet header */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */
    
    unsigned int size_ip;
    unsigned int size_tcp;

    // ethernet header 
    ethernet = (struct sniff_ethernet*)(packet);
    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
    } else  if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        printf("ARP\n");
    } else  if (ntohs(ethernet->ether_type) == ETHERTYPE_REVARP) {
        printf("Reverse ARP\n");
    }

    // ip header 
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // if not TCP or UDP -> skip
    if (ip->ip_p == IPPROTO_TCP) {
        printf("Protocol : TCP\n");
        tcp_packets++;
    } else if (ip->ip_p == IPPROTO_UDP) {
        printf("Protocol : UDP\n");
        udp_packets++;
        return; // REMOVE THIS 
    } else {
        printf("Not a TCP or UDP packet. Skipping...\n\n");
        return;
    }

    // skipping UDP for now only showing tcp, FIX LATER
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // inet_ntop - convert IPv4 and IPv6 addresses from binary to text form
    inet_ntop(AF_INET, &ip->ip_src, source_ip, sizeof(source_ip));
    if (source_ip == NULL){
        fprintf(stderr, "Error: Converting source_ip to string.");
        return;    
    }
    inet_ntop(AF_INET, &ip->ip_dst, dest_ip, sizeof(dest_ip));
    if (dest_ip == NULL){
        fprintf(stderr, "Error: Converting dest_ip to string.");
        return;    
    }

    payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    printf("TCP header length : %u\n", size_tcp);
    printf("TCP payload length: %u\n", header->len-size_tcp-size_ip-SIZE_ETHERNET);
    printf("TCP SOURCE IP : %s\n", source_ip);
    printf("TCP DESTINATION IP : %s\n", dest_ip);
    printf("TCP SOURCE PORT : %u\n", ntohs(tcp->th_sport));
    printf("TCP DESTINATION PORT : %u\n", ntohs(tcp->th_dport));
    printf("Payload in starts at: packet's header %p + %d bytes\n", &packet, SIZE_ETHERNET + size_ip + size_tcp);
    printf("Payload in memory at: %p\n",&payload);
    
    printf("Packet capture length: %d\n", header->caplen);
    printf("Packet total length: %d\n", header->len);
    tcp_packets_bytes+=header->len;
    //udp_packets_bytes+=header->len;
}

void show_statistics(){
    printf("\n   --- Showing Statistics ---\n");
    printf("Total number of packets received: %u\nTotal number of TCP packets received: %u\nTotal number of UDP packets received.: %u\nTotal bytes of TCP packets received.: %u\nTotal bytes of UDP packets received: %u\n", total_number_of_packets, tcp_packets, udp_packets, tcp_packets_bytes, udp_packets_bytes);
}