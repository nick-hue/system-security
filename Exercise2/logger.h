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
    - if file does not exist and we have write mode "w" or "w+" or "a" or "a+"-> return 0
    - if file exists and read mode "r", exists and write mode "w" or "w+", exists and append mode "a" or "a+" -> return 1
*/
int get_access_type(const char *path, const char *modeString);

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
void make_log(const char *path, int access_type, int access_flag);

#endif