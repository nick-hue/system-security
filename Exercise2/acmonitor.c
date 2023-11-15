#include <stdio.h>
#include "acmonitor.h"
#include <getopt.h>

int main(int argc, char *argv[]){
    int opt;
    char *filename;
    Mode mode;

    while ((opt = getopt(argc, argv, "i:mh")) != -1) {
        switch (opt) {
            case 'm':
                // print malicious users
                mode = PRINT_MALICIOUS;
                break;
            case 'i':
                // print table of users
                mode = FILE_INFO;
                filename = optarg;
                break;
            case 'h':
                // help message 
                mode = HELP;
                break;
            default:
                mode = EXIT_MODE;
        }
    }

    switch(mode){
        case PRINT_MALICIOUS:
            printf("Priting malicious users: \n");
            break;
        case FILE_INFO:
            printf("Show file info of file : %s\n", filename);
            break;
        case HELP:
            printf("[-m]: Prints malicious users\n[-i <filename>]: Prints table of users that modified the file given and the number of modifications\n[-h]: Help Message.\n");
            break;
        case EXIT_MODE:
            fprintf(stderr, "Error: while getting mode.\nUse -h flag to show more info about arguments.\n");
            exit(EXIT_FAILURE);
    }


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
    printf("Log File:\n%s\n\n\n\n", buffer);

    size_t log_array_size = getAmountOfLogs(f);
    Log log_array[log_array_size];
    size_t log_index = 0;

    char *line, *field, *info;
    char* line_saveptr = NULL;

    line = strtok_r(buffer, ";", &line_saveptr);

    char* field_saveptr = NULL;
    char* info_saveptr = NULL;

    Log currentLog;

    while (line != NULL) {

        field = strtok_r(line, ",", &field_saveptr);

        while (field != NULL) {           
            info = strtok_r(field, ":", &info_saveptr);
            while(info != NULL){
                printf("%s->", info);
                if ((strcmp(info, "UID") == 0) || (strcmp(info, "\nUID") == 0))
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    printf("UID --------------> %s", info);
                    currentLog.user_id = atoi(info);
                    break;
                } 
                else if (strcmp(info, " Filename") == 0) 
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    printf("FILename ist %s", info);
                    currentLog.filename = info;
                    break;
                } 
                else if (strcmp(info, " Date") == 0)
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    Date current_date = getDate(info);
                    currentLog.date = current_date;
                    displayDate(current_date);
                    break;
                } 
                else if (strcmp(info, " Timestamp") == 0)
                {
                    Timestamp current_timestamp;
                    info = strtok_r(NULL, ":", &info_saveptr);
                    currentLog.timestamp.hours = atoi(info);
                    info = strtok_r(NULL, ":", &info_saveptr);
                    currentLog.timestamp.minutes = atoi(info);
                    info = strtok_r(NULL, ":", &info_saveptr);
                    currentLog.timestamp.seconds = atoi(info);
                    printf("HERE");
                    displayTimestamp(currentLog.timestamp);
                    printf("here");
                    break;
                } 
                else if (strcmp(info, " Access Type") == 0)
                {
                    printf("Hereareraaerear");
                    info = strtok_r(NULL, ":", &info_saveptr);
                    currentLog.access_type = atoi(info);
                    break;
                } 
                else if (strcmp(info, " Access denied flag") == 0)
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    currentLog.access_denied_flag = atoi(info);
                    break;
                } 
                else if (strcmp(info, " File fingerprint") == 0)
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    currentLog.file_fingerprint = info;
                    break;
                } 
                else 
                {
                    if (strcmp(info, "\n") == 0){
                        break;
                    } else {
                        printf("Error: while trying to get data for making of the log.\n");
                        exit(1);
                    }                    
                }
                info = strtok_r(NULL, ":", &info_saveptr);
            }
            field = strtok_r(NULL, ",", &field_saveptr);
        }
        log_array[log_index] = currentLog;
        log_index++;
        line = strtok_r(NULL, ";", &line_saveptr);
    }
    
    printf("\n\n\n\n\n\nDisplaying logs\n");
    for (size_t i = 0; i < log_array_size; i++){
        displayLog(log_array[i]);
    }
    
    printf("\n");
    free(buffer);
    fclose(f);

    return 0;
}

Date getDate(char *dateString){
    Date date;

    if (sscanf(dateString, "%d/%d/%d", &date.day, &date.month, &date.year) == 3) {
        printf("Good date");
    } else {
        printf("Error parsing date");
    }
    return date;
}

size_t getAmountOfLogs(FILE *fp){
    size_t count = 0;
    char c;
    for (c = getc(fp); c != EOF; c = getc(fp)){
        if (c == '\n')
            count = count + 1; 
    }
    return count;   
}

void displayTimestamp(Timestamp stamp){
    printf("HERE1");
    printf("Timestamp: %02d-%02d-%02d\n", stamp.hours, stamp.minutes, stamp.seconds);
    printf("HERE2");
}

void displayDate(Date date){
    printf("Date: %02d-%02d-%d\n", date.day, date.month, date.year);
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
    printf("Access Type: %d, Access denied flag: %d, File fingerprint: %s", log.access_type, log.access_denied_flag, log.file_fingerprint);
    // displayFingerprint(log.file_fingerprint, log.fingerprint_size);
    printf("\n");
}