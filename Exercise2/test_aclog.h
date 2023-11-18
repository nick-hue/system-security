#ifndef TEST_ACLOG_H
#define TEST_ACLOG_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>


/* makes the file names for the total number of files given as argument */
char ** makeFiles(int total_files, size_t file_size);


#endif