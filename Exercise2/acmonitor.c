#include <stdio.h>
#include "acmonitor.h"

int main(){
    printf("Calling the fopen() function for WRITING ...\n");
    char str[] = "Hello World13123123132";

    FILE *f = fopen("file_logging.log", "r");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    rewind(f);

    char *buffer = (char *)malloc(file_size);
    size_t bytes_read = fread(buffer, 1, file_size, f);

    printf("Opened Log file:\n%s\n", buffer);


    Timestamp stamp = {
        9,9,9
    };


    Date date = {
        12,12,2012
    };
    printf("%d:%d:%d", stamp.hours, stamp.minutes, stamp.minutes);

    free(buffer);
    fclose(f);

    printf("Successfully opened file.\n");
    return 0;
}