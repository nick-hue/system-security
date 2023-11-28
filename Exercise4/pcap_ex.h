#ifndef PCAP_EX_H
#define PCAP_EX_H

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

typedef enum {
    INTERFACE,
    PACKET,
    FILTER,
    HELP,
    EXIT_MODE
} Mode;

#endif