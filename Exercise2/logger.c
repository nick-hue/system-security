#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>

size_t getSizeOfFile(FILE *file);

int get_access_type(const char *path, const char *modeString) {
    if ((strcmp(modeString, "w") == 0) && (access(path, F_OK) != 0)) return 0;      // create
    if (strcmp(modeString, "r") == 0) return 1;                                     // open
    if ((strcmp(modeString, "w") == 0) && (access(path, F_OK) == 0)) return 2;      // write
    return -1;
}

FILE *fopen(const char* path, const char* mode){
    printf("test function in path: %s\n", path);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
        
    printf("UID: %d\n", getuid());
    printf("Filename: %s\n", path);    
    printf("Date: %d-%02d-%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    printf("Timestamp: %02d:%02d:%02d\n", tm.tm_hour, tm.tm_min, tm.tm_sec);
    int access_type = get_access_type(path, mode);
    printf("Access Type: %d\n", access_type);
    
    int access_flag;
    if (access_type==0 || access_type== 2)
    {
        access_flag = access(path, W_OK);
    }
    else if (access_type == 1)
    {
        access_flag = access(path, R_OK);
    }
    else
    {
        access_flag = 1;
        printf("Error: bad access type\n");
    }
    access_flag = -access_flag; // to make the -1 into a 1 if the access function, 0 still is 0; 

    printf("Access denied flag: %d\n", access_flag);

    FILE* (*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *fp = (*original_fopen)(path, mode);
    if (!fp) {
        printf("failed to open file %s with mode %s\n", path, mode);
        return NULL;
    }

    FILE *hash_fp = (*original_fopen)(path, "r");
    if (hash_fp) {
        size_t file_size = getSizeOfFile(hash_fp);
        char *buffer = (char *)malloc(file_size);
        
        size_t bytes_read = fread(buffer, 1, file_size, hash_fp);    // reading the contents of the file
        //printf("File size: %ld\nBytes read: %ld\n", file_size, bytes_read);
        if (bytes_read != file_size){
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
        
        printf("File fingerprint: ");
        for (size_t i = 0; i < hash_length; i++)    
        {
            printf("%02x", md_value[i]);    
        }
        printf("\n");
        //printf("\n%s\n", buffer);

        FILE *fout = (*original_fopen)("file_logging.log", "w");
        // write hash to file
        for (size_t i = 0; i < hash_length; i++)    
        {
            fprintf(fout, "%02x", md_value[i]);
        }

        fclose(fout);
        free(buffer);
        }
    else{
        printf("Error: while trying to get file pointer to read contents from file.\n");
        exit(1);
    }


    return (*original_fopen)(path,mode);
}

size_t getSizeOfFile(FILE *file){ // file has to be already opened 
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    return size;
}
    