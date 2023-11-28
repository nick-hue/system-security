#ifndef NET_MONITOR_H
#define NET_MONITOR_H

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

typedef enum {
    INTERFACE,
    PACKET,
    FILTER,
    HELP,
    EXIT_MODE
} Mode;

#endif