#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>

/*  Returns the size of the file
    params: file, FILE* stream of current file you want the file of
    retunrn: size_t, size of file
*/
size_t getSizeOfFile(FILE *file);

/* 
    Writes in the log file the hash of the contents of the file that is given as argument 
*/
void log_hash_content(FILE *hash_fp);

/*
    Returns the access type of the current file
*/
int get_access_type(const char *path, const char *modeString);

/*
    Returns the flag if the access of the file was denied(1) or not(0).
*/
int get_access_denied_flag(const char * path, int access_type);

/*
    Makes a symlink of a file
*/
void make_symlink(const char *target, const char *sym_link_path);

/*
    Gets the path of the file that given symlink points to
*/
char * get_target_path_by_symlink(const char *symlinkPath);

/*
    Makes the entire log of the current opening / writing function 
*/
void make_log(const char *path, int access_type);

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

#endif