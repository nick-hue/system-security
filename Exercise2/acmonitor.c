#include <stdio.h>
#include "acmonitor.h"
#include <getopt.h>
#include <sys/types.h>

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
            // 1. get logs
            // ERROR : to teleutaio log sto log array einai duplicate tou proteleutaiou
            log_array = getLogArray(&log_array_size);
            
            printf("AFTER FUNCTION CALL %ld\n", log_array_size);
            
            printf("\n\nDisplaying logs\n");
            for (size_t i = 0; i < log_array_size; i++) {
                displayLog(&log_array[i]);
            }
          
            // 2. print only the users that have more than 7 access denied 
            size_t filenm_index = 0;
            int array_size =0 ;
            
            Mal_User* possible_MalUsers = (Mal_User *)calloc(log_array_size, sizeof(Mal_User));  
            int* malUser_array = (int*)calloc(log_array_size, sizeof(int));

            if (malUser_array == NULL || possible_MalUsers == NULL){
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }
                
            for (size_t i = 0; i < log_array_size; i++){
                if(log_array[i].access_denied_flag == 1){
                    int cur_uid = log_array[i].user_id;
                    char* cur_filenm = log_array[i].filename;
                    
                    size_t mal_index = 0;     //index of malUser_array

                    for(size_t i = 0; i < log_array_size; i++){
                        if(possible_MalUsers[i].user_id == 0){              //returns the first empty position
                            mal_index = i;
                            break;
                        }else if (possible_MalUsers[i].user_id == cur_uid){ 
                            mal_index = i;
                            break;
                        }
                    }

                    //If user not recorded, add him in the struct
                    if( possible_MalUsers[mal_index].user_id == 0){ 
                        possible_MalUsers[mal_index].user_id = cur_uid;
                        //add filename
                        possible_MalUsers[mal_index].filename[0] = cur_filenm;
                    }else{
                        size_t filenm_index = 0;
                        for(size_t i = 0; i < 8; i++){
                            if(possible_MalUsers[mal_index].filename[i] == NULL){       //give the first empty position
                                filenm_index = i;
                                break;
                            }
                            else if(strcmp(possible_MalUsers[mal_index].filename[i],cur_filenm) == 0){    
                                filenm_index = i;
                                break;
                            }
                        }

                        if (filenm_index < 7){  //We haven't exceeded the 7 unpermitted accesses
                            if(possible_MalUsers[mal_index].filename[filenm_index] == NULL){//
                                possible_MalUsers[mal_index].filename[filenm_index] = cur_filenm;
                            }else{  //Already recorded this file
                              continue;
                            }
                        }else{
                            if(malUser_array[0] == 0){
                                malUser_array[0] = cur_uid;
                                array_size++;
                            }else{   
                                //If space is not enough add more
                                if(array_size > log_array_size){
                                    malUser_array = realloc(malUser_array, (array_size + 1) * sizeof(int));
                                }
                                malUser_array[array_size] = cur_uid;
                                array_size++;
                            }
                         }
                       }
                  }
            }

            printf("\n\nDisplaying Malicious Users\n");
            for (size_t i = 0; i < array_size; i++) {
                printf("User Id: %d\n", malUser_array[i]);
            }

            free(possible_MalUsers);
            free(malUser_array);

            break;
        case FILE_INFO:
            printf("Show file info of file : %s\n", filename);
            // 1. get logs
            // 2. pare mono ta logs pou exoun gia log.filename = filename;
            // 3. print the user_id and the amount of times the user edited the file
            /*    USER    |   EDIT AMOUNT
            -----------------------------
                1000    |   4
                2000    |   5

            */
            log_array = getLogArray(&log_array_size);
            
            printf("AFTER FUNCTION CALL %ld\n", log_array_size);
            printf("\n\nDisplaying logs\n");
            for (size_t i = 0; i < log_array_size-1; i++) {
                displayLog(&log_array[i]);
            }

            printf("\tUSER\t|     EDIT AMOUNT\n-------------------------------------\n");
            for (int i = 0; i < 5; i++){
                printf("\t%d000\t|\t%d\n", i, i + 1000);
            }
            printf("-------------------------------------\n");
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

    //printf("Opened Log file:\n%ld\n", bytes_read);
    //printf("Log File:\n%s\n\n\n\n", buffer);

    size_t log_array_size = getAmountOfLogs(f);
    printf("logarraysize : %ld\n", log_array_size);
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
                printf("%s->", info);
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
                    //printf("FiLename is: %s", info);
                    currentLog.filename = strdup(info)+1;
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
                        exit(1);
                    }                    
                }
                info = strtok_r(NULL, ":", &info_saveptr);
            }
            field = strtok_r(NULL, ",", &field_saveptr);
        }
        
        line = strtok_r(NULL, ";", &line_saveptr);

       // printf("\n\nAdding current log to the array: \n");
       // displayLog(&currentLog);

        log_array[log_index] = currentLog;
        
       // displayLog(&log_array[log_index]);
        log_index++;
    }

    printf("\n");
    free(buffer);
    fclose(f);

    *size_of_array = log_array_size;

    return log_array;
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
        if (c == ';')
            count = count + 1; 
    }
    return count;   
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