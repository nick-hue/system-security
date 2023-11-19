#include "acmonitor.h"

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
    // checking if the user gave no arguments
    if (optind < 2) {
        fprintf(stderr, "Error: No arguments provided.\nUse -h flag to show more info about arguments.\n");
        exit(EXIT_FAILURE);
    }
    // checking if the user gave more arguments ./acmonitor -i -m error
    if ((optind > 2 && mode!=FILE_INFO) || (optind > 3 && mode==FILE_INFO)){
        fprintf(stderr, "Error: Too many arguments provided.\nNumber of arguments provided: %d\nUse -h flag to show more info about arguments.\n", optind);
        exit(EXIT_FAILURE);
    }

    size_t log_array_size;
    Log *log_array;

    switch(mode){
        case PRINT_MALICIOUS:
            printf("Priting malicious users: \n");
            // 1. get logs
            // ERROR : to teleutaio log sto log array einai duplicate tou proteleutaiou
            log_array = getLogArray(&log_array_size);
            
            printf("AFTER FUNCTION CALL %ld\n", log_array_size);
            
            printf("\n\nDisplaying logs\n");
            for (size_t i = 0; i < log_array_size-1; i++) {
                displayLog(&log_array[i]);
            }

            // 2. print only the users that have more than 7 access denied 

            
            break;
        case FILE_INFO:
            printf("Show file info of file : %s\n", filename);
            
            log_array = getLogArray(&log_array_size);

            // get only the logs that have the given filename 
            size_t size;
            Log *logs = getLogsByFilename(log_array, log_array_size, filename, &size);

            // get all the users that have modified the specific file
            size_t unique_UIDS_count;
            int *unique_UIDS = getUniqueUIDS(logs, size, &unique_UIDS_count);
            int *UID_access_count = (int *)calloc(unique_UIDS_count, sizeof(int)); // amount of times modified of the specific user
            if (UID_access_count == NULL) {
                perror("Memory allocation error");
                return 1;
            }

            for (int j = 0; j < unique_UIDS_count; j++){ 
                for (size_t i = 0; i < size; i++){
                    if (unique_UIDS[j] == logs[i].user_id){
                        displayLog(&logs[i]);
                        if (isUniqueFingerprint(logs, i, logs[i].file_fingerprint)) {
                            UID_access_count[j]++;
                        }
                    }
                }
            printf("-----------------------------------------\n");
            }
            printf("-----------------------------------------\n|\tUSER\t|     EDIT AMOUNT\t|\n-----------------------------------------\n");
            for (size_t i = 0; i < unique_UIDS_count; i++){
                printf("|\t%d\t|\t%d\t\t|\n", unique_UIDS[i], UID_access_count[i]);
            }
            printf("-----------------------------------------\n");

            free(logs);
            free(UID_access_count);
            free(unique_UIDS);

            break;
        case HELP:
            printf("[-m]: Prints malicious users\n[-i <filename>]: Prints table of users that modified the file given and the number of modifications\n[-h]: Help Message.\n");
            break;
        case EXIT_MODE:
            fprintf(stderr, "Error: while getting mode.\nUse -h flag to show more info about arguments.\n");
            exit(EXIT_FAILURE);
    }

    return 0;
}

Log * getLogArray(size_t *size_of_array){

    FILE *f = fopen("file_logging.log", "r");
    if (!f){
        printf("Error: opening file\n");
        exit(1);
    }
    
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    rewind(f);

    char *buffer = (char *)malloc(file_size);
    size_t bytes_read = fread(buffer, 1, file_size, f);
    rewind(f);

    size_t log_array_size = getAmountOfLogs(f)+1;
    Log *log_array = (Log *)malloc(log_array_size*sizeof(Log));
    size_t log_index = 0;

    char *line, *field, *info;

    char* line_saveptr = NULL;
    char* field_saveptr = NULL;
    char* info_saveptr = NULL;

    Log currentLog;

    line = strtok_r(buffer, ";", &line_saveptr);

    while (line != NULL) {

        field = strtok_r(line, ",", &field_saveptr);

        while (field != NULL) {           
            info = strtok_r(field, ":", &info_saveptr);
            while(info != NULL){
                //printf("%s->", info);
                if ((strcmp(info, "UID") == 0) || (strcmp(info, "\nUID") == 0))
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    //printf("UID --------------> %s", info);
                    currentLog.user_id = atoi(info);
                    break;
                } 
                else if (strcmp(info, " Filename") == 0) 
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    //printf("FILename ist %s", info);
                    currentLog.filename = strdup(info) + 1; // makes the filename from " testfile.txt" -> "testfile.txt"
                    break;
                } 
                else if (strcmp(info, " Date") == 0)
                {
                    info = strtok_r(NULL, ":", &info_saveptr);
                    Date current_date = getDate(info);
                    currentLog.date = current_date;
                    //displayDate(&current_date);
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
                    //displayTimestamp(&currentLog.timestamp);
                    break;
                } 
                else if (strcmp(info, " Access Type") == 0)
                {
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
                    currentLog.file_fingerprint = strdup(info);
                    //printf("%s", currentLog.file_fingerprint);
                    break;
                } 
                else 
                {
                    if (strcmp(info, "\n") == 0){
                        break;
                    } else {
                        printf("Error: while trying to get data for making of the log.\n");
                        //exit(1);
                    }                    
                }
                info = strtok_r(NULL, ":", &info_saveptr);
            }
            field = strtok_r(NULL, ",", &field_saveptr);
        }
        
        line = strtok_r(NULL, ";", &line_saveptr);

        //printf("\n\nAdding current log to the array: \n");
        //displayLog(&currentLog);

        log_array[log_index] = currentLog;
        
        //displayLog(&log_array[log_index]);
        log_index++;
    }

    printf("\n");
    free(buffer);
    fclose(f);

    *size_of_array = log_array_size;

    return log_array;
}

Log * getLogsByFilename(Log *log_array, size_t log_array_size, char *filename, size_t *size_of_array){

    Log *logs = (Log *)malloc(sizeof(Log)); // logs array for which have the filename
    if (logs == NULL) {
        perror("Memory allocation error");
        exit(1);
    }
    size_t size = 1;

    for (size_t i = 0; i < log_array_size; i++){
        if (strcmp(log_array[i].filename, filename) == 0){
            printf("size = %ld\n", size*sizeof(Log));
            if (size == 1){
                logs[0] = log_array[i];
                size++;
            } else {
                Log *temp = (Log *)realloc(logs, size * sizeof(Log));                    
                if (!temp) {
                    perror("error with realloc");
                    free(logs);
                    exit(1);
                }
                logs = temp;
                logs[size-1] = log_array[i];
                size++;
            }
        }
    }
        
    size--;
    
    *size_of_array = size;

    return logs;
}
Date getDate(char *dateString){
    Date date;

    if (sscanf(dateString, "%d/%d/%d", &date.day, &date.month, &date.year) == 3) {
        //printf("Good date");
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

int isUniqueFingerprint(Log *logs, int currentIndex, const char *fingerprint){
    for (int i = 0; i < currentIndex; i++) {
        if ((strcmp(logs[i].file_fingerprint, fingerprint) == 0)) {
            return 0; // Not unique
        }
    }
    return 1; // Unique
}

int* getUniqueUIDS(Log *logs, size_t logCount, size_t *uniqueUidCount) {
    
    int *uniqueUids = (int *)malloc(sizeof(int));
    if (uniqueUids == NULL) {
        perror("Memory allocation error");
        exit(1);
    }
    size_t uidCount = 1;

    // Loop through each log entry in the array
    for (size_t i = 0; i < logCount; i++) {
        int isUnique = 1;
        for (int j = 0; j < uidCount; j++) {
            if (uniqueUids[j] == logs[i].user_id) {
                isUnique = 0;
                break;
            }
        }
        // if its the first item of the array
        if (uidCount == 1){
            uniqueUids[0] = logs[i].user_id;
            uidCount++;
            continue;
        }
        // If it's unique, add it to the array
        if (isUnique) {
            int *temp = (int *)realloc(uniqueUids, uidCount * sizeof(int));                    
            if (!temp) {
                perror("error with realloc");
                free(logs);
                exit(1);
            }
            uniqueUids = temp;
            uniqueUids[uidCount-1] = logs[i].user_id;
            uidCount++;
        }
    }

    // Set the count of unique UIDs
    uidCount--;
    *uniqueUidCount = uidCount;

    return uniqueUids;
}

void displayTimestamp(Timestamp *stamp){
    printf("Timestamp: %02d-%02d-%02d\n", stamp->hours, stamp->minutes, stamp->seconds);
}

void displayDate(Date *date){
    printf("Date: %02d-%02d-%d\n", date->day, date->month, date->year);
}

void displayFingerprint(unsigned char *bytes, size_t size){
    for (size_t i = 0; i < size; i++){
        printf("%02x", bytes[i]);
    }
}

void displayLog(Log *log){
    printf("LOG=> UID: %d, Filename: %s, ", log->user_id, log->filename);
    printf("Date: %02d/%02d/%d, ", log->date.day, log->date.month, log->date.year);
    printf("Timestamp: %02d:%02d:%02d, ", log->timestamp.hours, log->timestamp.minutes, log->timestamp.seconds);
    printf("Access Type: %d, Access denied flag: %d, File fingerprint: %s", log->access_type, log->access_denied_flag, log->file_fingerprint);
    printf("\n");
}