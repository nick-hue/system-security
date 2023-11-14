#include <stdio.h>
#include "acmonitor.h"

int main(){

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

    printf("Opened Log file:\n%ld\n", bytes_read);
    
    char *line, *field, *info;
    char* line_saveptr = NULL;

    line = strtok_r(buffer, ";", &line_saveptr);
    printf("LINE: %s\n", line);

    char* field_saveptr = NULL;
    char* info_saveptr = NULL;

    while (line != NULL) {
        printf("Log Entry:\n");

        field = strtok_r(line, ",", &field_saveptr);
        while (field != NULL) {
            //printf("%s\n", field);
            
            info = strtok_r(field, ":", &info_saveptr);
            while(info != NULL){
                printf("%s ", info);
                info = strtok_r(NULL, ":", &info_saveptr);
            }
            field = strtok_r(NULL, ",", &field_saveptr);
        }

        line = strtok_r(NULL, ";", &line_saveptr);
    }
    
    printf("\n");
    free(buffer);
    fclose(f);

    return 0;
}


void displayTimestamp(Timestamp stamp){
    printf("Timestamp: %02d:%02d:%02d\n", stamp.hours, stamp.minutes, stamp.seconds);
}

void displayDate(Date date){
    printf("Date: %02d/%02d/%d\n", date.day, date.month, date.year);
}

void displayFingerprint(unsigned char *bytes, size_t size){
    for (size_t i = 0; i < size; i++){
        printf("%02x", bytes[i]);
    }
}

void displayLog(Log log){
    printf("LOG: \nUID: %d, Filename: %s", log.user_id, log.filename);
    displayDate(log.date);
    displayTimestamp(log.timestamp);
    printf("Access Type: %d, Access denied flag: %d, File fingerprint: ", log.access_type, log.access_denied_flag);
    displayFingerprint(log.file_fingerprint, log.fingerprint_size);
    printf("\n");
}