#include "net_monitor.h"

int main(int argc, char *argv[]) {
    int opt;
    char *input;
    Mode mode;

    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                mode = INTERFACE;
                input = strdup(optarg);
                printf("%s\n", input);
                break;
            case 'r':
                mode = PACKET;
                input = strdup(optarg);
                printf("%s\n", input);
                break;  
            case 'f':
                mode = FILTER;
                input = strdup(optarg);
                printf("%s\n", input);
                break;  
            case 'h':
                mode = HELP;
                printf("Help mode\n", input);
                break;
            default:
                mode = EXIT_MODE;
                fprintf(stderr, "Error invalid arguments given.\nUse -h flag to show more info about arguments.\n");
                exit(1);
        }
    }

    return 0;
}