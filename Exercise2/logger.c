#define _GNU_SOURCE

#include "logger.h"

FILE* (*original_fopen)(const char*, const char*);
FILE *fout = NULL;

__attribute__((constructor))
void initialize() {
    // Initialization code here
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    if (access("file_logging.log", F_OK) == 0){
        // append to the logging file if it exists
        fout = original_fopen("file_logging.log", "a");
    }
    else{
        // create the logging file if it does not exist
        fout = original_fopen("file_logging.log", "w");
    }

    printf("\n\nCustom library loaded. Overriding fopen and fwrite.\n");
}

__attribute__((destructor))
void finalize() {

    if (fout) {
        fclose(fout);
    }
    
}

FILE *fopen(const char* path, const char* mode){
    int access_type = get_access_type(path, mode);
    FILE* f = (*original_fopen)(path,mode);

    if (strcmp(mode, "w")==0 || strcmp(mode, "a")==0){
        char sym_path[1024];
        sprintf(sym_path, "symlink_file_%d", fileno(f));
        make_symlink(path, sym_path);
    }
    int access_denied_flag;

    if ((strcmp(mode, "w") == 0) || (strcmp(mode, "w+") == 0) || (strcmp(mode, "a") == 0) || (strcmp(mode, "a+") == 0)){
        access_denied_flag = -access(path, W_OK);
    } else if ((strcmp(mode, "r") == 0) || (strcmp(mode, "r+") == 0)){
        access_denied_flag = -access(path, R_OK);
    } else {
        printf("Should not be here maybe mode= 'x'\n");
        access_denied_flag = 999;
    }

    // open the file to get its contents 
    make_log(path, access_type, access_denied_flag);
    
    char tmp[3] = " ;\0";
    fprintf(fout, "%s", tmp); // the fprintf function runs the fwrite function if it does not take the "%s" argument

    return f;
}

size_t fwrite(const void *ptr, size_t size_of_element, size_t number_of_elements, FILE *stream){   
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE *);
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    size_t written = (*original_fwrite)(ptr, size_of_element, number_of_elements, stream);
    
    char *targetPath = (char *)malloc(1024);
    char symlinkPath[1024];
    
    sprintf(symlinkPath, "symlink_file_%d", fileno(stream));

    targetPath = get_target_path_by_symlink(symlinkPath);

    if (remove(symlinkPath) == 0){
        //("Simlink deleted successfully\n");
    }
    else{
        printf("Unable to delete the file\n");
        exit(1);
    }

    int access_type = 2;
    int access_denied_flag = -access(targetPath, W_OK); // if 0->0, if -1->1

    make_log(targetPath, access_type, access_denied_flag);
   
    char tmp[3] = " ;\0";
    fprintf(fout, "%s", tmp); // the fprintf function runs the fwrite function if it does not take the "%s" argument

    return written;
}

void log_hash_content(FILE *hash_fp){
    if (!hash_fp) {
        //printf("Error: while trying to get file pointer to read contents from file.\n");
        //char tmp[4] = " ;\n\0";
        //fprintf(fout, "%s", tmp); // the fprintf function runs the fwrite function if it does not take the "%s" argument
        return;
        //exit(1);
    }

    size_t file_size = getSizeOfFile(hash_fp);     // getting the size of the file to hash
    char *buffer = (char *)malloc(file_size);      // allocating memory 

    size_t bytes_read = fread(buffer, 1, file_size, hash_fp);    // reading the contents of the file
    if (bytes_read != file_size){                                // checking if the bytes read are the same with the memory we allocated
        printf("Error: while reading from file\n");
        exit(1);
    }

    unsigned int hash_length;
    unsigned char md_value[EVP_MAX_MD_SIZE];  

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *EVP_md5();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, buffer, file_size);
    EVP_DigestFinal_ex(mdctx, md_value, &hash_length);

    // write hash to file
    for (size_t i = 0; i < hash_length; i++)    
    {
        //printf("%02x", md_value[i]);
        fprintf(fout, "%02x", md_value[i]);
    }

    fclose(hash_fp);
    free(buffer);
}

void make_log(const char *path, int access_type, int access_flag){
    time_t t = time(NULL);
    struct tm tm = *localtime(&t); 

    FILE *hash_fp = (*original_fopen)(path, "r");
    // write log to logfile 
    
    if (NULL != fout) {
        fseek (fout, 0, SEEK_END);
        long si = ftell(fout);

        if (si == 0) {
            fprintf(fout, "UID: %d, Filename: %s, Date: %02d/%02d/%d, Timestamp: %02d:%02d:%02d, Access Type: %d, Access denied flag: %d, File fingerprint: ", getuid(), path, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, access_type, access_flag);
        }
        else {
            fprintf(fout, "\nUID: %d, Filename: %s, Date: %02d/%02d/%d, Timestamp: %02d:%02d:%02d, Access Type: %d, Access denied flag: %d, File fingerprint: ", getuid(), path, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, access_type, access_flag);
        }
    }
    
    log_hash_content(hash_fp);
}

int get_access_type(const char *path, const char *modeString){
    if (((strcmp(modeString, "w") == 0) || (strcmp(modeString, "w+") == 0) || (strcmp(modeString, "a") == 0) || (strcmp(modeString, "a+") == 0)) && (access(path, F_OK) != 0)) return 0;      
    if (((strcmp(modeString, "r") == 0) || (strcmp(modeString, "r+") == 0) || (strcmp(modeString, "w") == 0) || (strcmp(modeString, "w+") == 0) || (strcmp(modeString, "a") == 0) || (strcmp(modeString, "a+") == 0)) && (access(path, F_OK) == 0)) {
        return 1;
    }                                     
    return -1;
}

void make_symlink(const char *target, const char *sym_link_path){
    if (symlink(target, sym_link_path) == -1) {
        //printf("file: %s\n", target);
        perror("symlink failed");
        exit(1);
    } else {
        //printf("Symlink created: %s -> %s\n", sym_link_path, target);
    }
}

char * get_target_path_by_symlink(const char *symlinkPath){
    char *targetPath = (char *)malloc(1024);
    ssize_t len;

    len = readlink(symlinkPath, targetPath, 1023);
    
    if (len == -1) {
        perror("readlink");
        exit(EXIT_FAILURE);
    }

    targetPath[len] = '\0';

    //printf("The symlink '%s' points to '%s'\n", symlinkPath, targetPath);
    return targetPath;
}

size_t getSizeOfFile(FILE *file){ // file has to be already opened 
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    return size;
}