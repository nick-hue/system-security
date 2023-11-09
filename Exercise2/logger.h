#include <unistd.h>

typedef struct Log {
    uid_t user_id;
    char *filename;
    Date date;
    Timestamp timestamp;
    int access_type;
    int access_denied_flag;
    unsigned char *file_fingerprint;
} Log;

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
