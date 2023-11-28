#include "pcap_ex.h"

int main(int argc, char *argv[]) {
    int opt;
    char *input = NULL, *filter = NULL;
    Mode mode;

    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                mode = INTERFACE;
                input = optarg;
                break;
            case 'r':
                mode = PACKET;
                input = strdup(optarg);
                break;  
            case 'f':
                mode = FILTER;
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
            break;

        case HELP:
            printf("-i Select the network interface name (e.g., eth0)\n-r Packet capture file name (e.g., test.pcap)\n-f Filter expression in string format (e.g., port 8080)\n-h Help message, which show the usage of each parameter\n");                
            break;
        case EXIT_MODE:
            fprintf(stderr, "Error: while getting mode.\nUse -h flag to show more info about arguments.\n");
            exit(EXIT_FAILURE);
    }

    printf("interface : %s\nfilter : %s\n", input, filter);

    return 0;
}