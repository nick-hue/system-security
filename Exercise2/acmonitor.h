#ifndef AC_MONITOR_H
#define AC_MONITOR_H

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

typedef struct Date {
    int day;
    int month;
    int year;
} Date;

typedef struct Timestamp {
    int hours;
    int minutes;
    int seconds;
} Timestamp;

typedef struct Log {
    int user_id;// change to uid_t
    char *filename;
    Date date;
    Timestamp timestamp;
    int access_type;
    int access_denied_flag;
    unsigned char *file_fingerprint;
    size_t fingerprint_size;
} Log;

void dislayTimestamp(Timestamp stamp);
void displayDate(Date date);
void displayFingerprint(unsigned char *bytes, size_t size);
void displayLog(Log log);
size_t getAmountOfLogs(FILE *fp, char findChar);



#endif