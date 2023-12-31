#ifndef AC_MONITOR_H
#define AC_MONITOR_H

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#define MAX_SIZE 8

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
    uid_t user_id;// change to uid_t
    char *filename;
    Date date;
    Timestamp timestamp;
    int access_type;
    int access_denied_flag;
    char *file_fingerprint;
} Log;

typedef struct Mal_User {
    int user_id;
    char* filename[MAX_SIZE]; // = (char*)malloc(8*sizeof(char));
} Mal_User;

typedef enum {
    PRINT_MALICIOUS,
    FILE_INFO,
    HELP,
    EXIT_MODE
} Mode;

void displayTimestamp(Timestamp *stamp);
void displayDate(Date *date);
void displayFingerprint(unsigned char *bytes, size_t size);
void displayLog(Log *log);
Log * getLogArray();
Log * getLogsByFilename(Log *log_array, size_t log_array_size, char *filename, size_t *size_of_array);
size_t getAmountOfLogs(FILE *fp);
Date getDate(char *dateString);
int isUniqueFingerprint(Log *logs, int currentIndex, const char *fingerprint);
int* getUniqueUIDS(Log *logs, size_t logCount, size_t *uniqueUidCount);

#endif