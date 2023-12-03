#include "pcap_ex.h"

unsigned int total_number_of_NetworkFLows = 0;   /* Total number of total_number_of_NetworkFLows received */
unsigned int tcpNetworkFLows_packets = 0;               /* Total number of TCP packets received. */
unsigned int udpNetworkFLows_packets = 0;               /* Total number of UDP packets received. */
unsigned int total_number_of_packets = 0;   /* Total number of packets received */
unsigned int tcp_packets = 0;               /* Total number of TCP packets received. */
unsigned int udp_packets = 0;               /* Total number of UDP packets received. */
unsigned int tcp_packets_bytes = 0;         /* Total bytes of TCP packets received. */
unsigned int udp_packets_bytes = 0;         /* Total bytes of UDP packets received. */
struct PacketInfo tcp_transmitted_packets[MAX_PACKETS];
int num_transmitted_packets = 0;

int main(int argc, char *argv[]) {
    int opt;
    char *dev = NULL, *pcap_name = NULL, *filter = NULL;
    Mode mode;

    FILE* f = fopen("log.txt", "w");
    if (f == NULL) {
        perror("Error opening file");
        return -1;
    }

    fclose(f);
    
    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                mode = INTERFACE;
                dev = optarg;
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

    pcap_t *handle;			            /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	    /* Error string */
    bpf_u_int32 net;                    /* The IP of our sniffing device */
    struct bpf_program fp;		        /* The compiled filter */

    /*for online mode*/
    int packet_count_limit = -1;
    int timeout_limit = 10000;          /* 10 seconds in milliseconds */
    bpf_u_int32 mask;                   /* The netmask of our sniffinf device */

    /*for offline mode*/
    struct pcap_pkthdr header;	        /* The header that pcap gives us */
    const unsigned char *packet;		/* The actual packet */


    switch(mode){
        case INTERFACE:
            // online mode
            //My device interface name: wlp2s0
            /*Print the device*/
            if (dev == NULL) {
                fprintf(stderr, "Device is not given \n");
                return 2;
            }

            /*Aquire on of the device's IPv4 network number and the subnet mask*/
            if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
                fprintf(stderr, "Can't get netmask for device: %s\n", dev);
                net = 0;
                mask = 0;
            }

            /* Open device for live capture */
            handle = pcap_open_live(dev, BUFSIZ, packet_count_limit, timeout_limit, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return 1;
            }

            // if filter exists apply it, if not dont ¯\_(ツ)_/¯
            if (filter){ 
                printf("filter exists\nfilter : %s\n", filter);

                if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
                    return 1;
                }
                
                if (pcap_setfilter(handle, &fp) == -1) {
                    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
                    return 1;
                }
            } 

            printf("Listening...");
            if (pcap_loop(handle, packet_count_limit, got_packet_online, NULL) < 0) {
                fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
                return 1;
            }

            pcap_close(handle);
            break;
        case PACKET:
            // offline mode i think
            handle = pcap_open_offline(pcap_name, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open pcap file %s: %s\n", pcap_name, errbuf);
                return 1;
            }

            // if filter exists apply it, if not dont ¯\_(ツ)_/¯
            if (filter){ 
                printf("filter exists\nfilter : %s\n", filter);

                if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
                    return 1;
                }
                
                if (pcap_setfilter(handle, &fp) == -1) {
                    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
                    return 1;
                }
            } 
          
            if (pcap_loop(handle, 0, got_packet_offline, NULL) < 0) {
                fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
                return 1;
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

void got_packet_online(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){	
    const struct sniff_ethernet *ethernet;  /* The ethernet header *///if not ip skip
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;               /* The TCP header */
    const struct udphdr *udp;               /* The UDP header */
    bool is_retransmission;

    const char *payload;                    /* Packet payload */
    
    unsigned int size_ip;
    unsigned int size_tcp;
    unsigned int size_udp;

    total_number_of_packets++;

    // ethernet header 
    ethernet = (struct sniff_ethernet*)(packet);
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP){
        //printf("Uknown ether type, skipping...");
        return;
    }

    total_number_of_packets++;
    // ip header 
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        //printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // if not TCP or UDP -> skip
    if (ip->ip_p == IPPROTO_TCP) {
        tcp_packets++;

        // tcp header
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

        /*ntohl converts 32-bit unsigned integer from network byte order to host byte order*/
        tcp_seq seq_number = ntohl(tcp->th_seq);
        tcp_seq ack_number = ntohl(tcp->th_ack);

        // Check for retransmission
        is_retransmission = false;
        for(int i=0; i< num_transmitted_packets-1; i++){
            if(tcp_transmitted_packets[i].seq == seq_number && ack_number < tcp_transmitted_packets[i+1].seq) {
                is_retransmission = true;
                break;
            }
        }

        /*Record transmitted packet*/
        if(!is_retransmission && num_transmitted_packets < MAX_PACKETS){
            tcp_transmitted_packets[num_transmitted_packets].seq = seq_number;
            num_transmitted_packets++;
        }

        payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        
        FILE* f = fopen("log.txt", "a");
        if (f == NULL) {
            perror("Error opening file");
            return ;
        }

        if(is_retransmission){
            fprintf(f, "Retransmitted\n");
        }
        fprintf(f, "Protocol : TCP\n");
        fprintf(f, "TCP header length : %u\n", size_tcp);
        fprintf(f, "TCP payload length: %u\n", header->len - size_tcp - size_ip - SIZE_ETHERNET);
        fprintf(f, "TCP SOURCE IP : %s\n", source_ip);
        fprintf(f, "TCP DESTINATION IP : %s\n", dest_ip);
        fprintf(f, "TCP SOURCE PORT : %u\n", ntohs(tcp->th_sport));
        fprintf(f, "TCP DESTINATION PORT : %u\n", ntohs(tcp->th_dport));
        fprintf(f, "Payload starts at: TCP packet's header %p + %d bytes\n", &packet, SIZE_ETHERNET + size_ip + size_tcp);
        fprintf(f, "Payload in memory at: %p\n", &payload);
        fprintf(f, "Packet total length: %d\n\n", header->len);

        fclose(f);
        
        tcp_packets_bytes+=header->len;

    } else if (ip->ip_p == IPPROTO_UDP) {
        udp_packets++;

        // udp header
        udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
        size_udp = 8; // udp header is always 8 bytes 
        
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

        payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
        
        FILE *file = fopen("log.txt", "a");
        if (file == NULL) {
            perror("Error opening file");
            return;
        }

        fprintf(file, "Protocol : UDP\n");
        fprintf(file, "UDP header length : %u\n", size_udp);
        fprintf(file, "UDP payload length: %u\n", header->len - size_udp - size_ip - SIZE_ETHERNET);
        fprintf(file, "UDP SOURCE IP : %s\n", source_ip);
        fprintf(file, "UDP DESTINATION IP : %s\n", dest_ip);
        fprintf(file, "UDP SOURCE PORT : %hu\n", ntohs(udp->uh_sport));
        fprintf(file, "UDP DESTINATION PORT : %hu\n", ntohs(udp->uh_dport));
        fprintf(file, "Payload starts at: UDP packet's header %p + %d bytes\n", &packet, SIZE_ETHERNET + size_ip + size_udp);
        fprintf(file, "Payload in memory at: %p\n", &payload);
        fprintf(file, "Packet total length: %d\n\n", header->len);

        fclose(file);

        udp_packets_bytes+=header->len;
    } else {
        printf("Not a TCP or UDP packet. Skipping...\n\n");
        return;
    }

    
}

void got_packet_offline(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    printf("\n\n");	

    const struct sniff_ethernet *ethernet;  /* The ethernet header */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct udphdr *udp;               /* The UDP header */
    bool is_retransmission;

    const char *payload;                    /* Packet payload */
    
    unsigned int size_ip;
    unsigned int size_tcp;
    unsigned int size_udp;

    // ethernet header 
    ethernet = (struct sniff_ethernet*)(packet);
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP){
        //printf("Uknown ether type, skipping...");
        return;
    }

    // ip header 
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
       // printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // if not TCP or UDP -> skip
    if (ip->ip_p == IPPROTO_TCP) {
        tcp_packets++;

        // tcp header
        tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }

        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        // inet_ntop - convert IPv4 and IPv6 addresses from binary to text form
        inet_ntop(AF_INET, &ip->ip_src, source_ip, INET_ADDRSTRLEN);
        if (source_ip == NULL){
            fprintf(stderr, "Error: Converting source_ip to string.");
            return;    
        }
        inet_ntop(AF_INET, &ip->ip_dst, dest_ip, INET_ADDRSTRLEN);
        if (dest_ip == NULL){
            fprintf(stderr, "Error: Converting dest_ip to string.");
            return;    
        }

        /*ntohl converts 32-bit unsigned integer from network byte order to host byte order*/
        tcp_seq seq_number = ntohl(tcp->th_seq);
        tcp_seq ack_number = ntohl(tcp->th_ack);

        // Check for retransmission
        is_retransmission = false;
        for(int i=0; i< num_transmitted_packets-1; i++){
            if(tcp_transmitted_packets[i].seq == seq_number && ack_number < tcp_transmitted_packets[i+1].seq) {
                is_retransmission = true;
                break;
            }
        }

        /*Record transmitted packet*/
        if(!is_retransmission && num_transmitted_packets < MAX_PACKETS){
            tcp_transmitted_packets[num_transmitted_packets].seq = seq_number;
            num_transmitted_packets++;
        }



        payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        
        if(is_retransmission){
            printf("Retransmitted\n");
        }
        printf("Protocol : TCP\n");
        printf("TCP header length : %u\n", size_tcp);
        printf("TCP payload length: %u\n", header->len-size_tcp-size_ip-SIZE_ETHERNET);
        printf("TCP SOURCE IP : %s\n", source_ip);
        printf("TCP DESTINATION IP : %s\n", dest_ip);
        printf("TCP SOURCE PORT : %u\n", ntohs(tcp->th_sport));
        printf("TCP DESTINATION PORT : %u\n", ntohs(tcp->th_dport));
        printf("Payload starts at: TCP packet's header %p + %d bytes\n", &packet, SIZE_ETHERNET + size_ip + size_tcp);
        printf("Payload in memory at: %p\n",&payload);
        printf("Packet total length: %d\n", header->len);
        
        tcp_packets_bytes+=header->len;

    } else if (ip->ip_p == IPPROTO_UDP) {
        udp_packets++;

        // udp header
        udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
        size_udp = 8; // udp header is always 8 bytes 
        
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        // inet_ntop - convert IPv4 and IPv6 addresses from binary to text form
        inet_ntop(AF_INET, &ip->ip_src, source_ip, INET_ADDRSTRLEN);
        if (source_ip == NULL){
            fprintf(stderr, "Error: Converting source_ip to string.");
            return;    
        }
        inet_ntop(AF_INET, &ip->ip_dst, dest_ip, INET_ADDRSTRLEN);
        if (dest_ip == NULL){
            fprintf(stderr, "Error: Converting dest_ip to string.");
            return;    
        }

        payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
        
        printf("Protocol : UDP\n");
        printf("UDP header length : %u\n", size_udp);
        printf("UDP payload length: %u\n", header->len-size_udp-size_ip-SIZE_ETHERNET);
        printf("UDP SOURCE IP : %s\n", source_ip);
        printf("UDP DESTINATION IP : %s\n", dest_ip);
        printf("UDP SOURCE PORT : %hu\n", ntohs(udp->uh_sport));        
        printf("UDP DESTINATION PORT : %hu\n", ntohs(udp->uh_dport));        
        printf("Payload starts at: UDP packet's header %p + %d bytes\n", &packet, SIZE_ETHERNET + size_ip + size_udp);
        printf("Payload in memory at: %p\n",&payload);
        printf("Packet total length: %d\n", header->len);

        udp_packets_bytes+=header->len;
    } else {
        printf("Not a TCP or UDP packet. Skipping...\n\n");
        return;
    }
}

void show_statistics(){
    printf("\n   --- Showing Statistics ---\n");
    printf("Total number of packets received: %u\nTotal number of TCP packets received: %u\nTotal number of UDP packets received: %u\nTotal bytes of TCP packets received: %u bytes\nTotal bytes of UDP packets received: %u bytes\n", total_number_of_packets, tcp_packets, udp_packets, tcp_packets_bytes, udp_packets_bytes);
}