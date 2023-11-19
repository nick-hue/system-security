#include "test_aclog.h"

int main(){
	int total_files = 16;
    size_t buffer_size, file_size = 12;
	FILE *f;

    char **files = makeFiles(total_files, file_size);

    for (int i = 0; i<total_files; i++){
        printf("Opening file: %s\n", files[i]);

        f = fopen(files[i], "w");
        if (!f){
            fprintf(stderr, "Failed to open file: %s", files[i]);
            continue;
        }
        printf("%ld\n", strlen(files[i]));

        char file_string[strlen(files[i])+12];

        sprintf(file_string, "thisisfile:%s", files[i]);

        buffer_size = fwrite(file_string, strlen(files[i])+11, 1, f);
        fclose(f);
    }

    // files 0 -> 3 no reading 
    for (int i = 0; i < 4; i++){
        printf("Opening file: %s\n", files[i]);
        
        // switching permissions to -> --wx-wx-wx
        chmod(files[i], S_IWUSR | S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH);
        f = fopen(files[i], "r+");
        if (!f){
            fprintf(stderr, "Failed to open file: %s\n", files[i]);
            continue;
        }
        fclose(f);
    }

    // files 4 -> 7 no reading 
    for (int i = 4; i < 8; i++){
        printf("Opening file: %s\n", files[i]);

        // switching permissions to -> -r-xr-xr-x
        chmod(files[i], S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        f = fopen(files[i], "w+");
        if (!f){
            fprintf(stderr, "Failed to open file: %s\n", files[i]);
            continue;
        }
        char testString[] = "testasfadsfafsdsdf";   // this should not be written
        fwrite(strdup(testString), 1, strlen(testString), f);
        fclose(f);
    }

    // files 8 -> 11 no reading - no writing
    for (int i = 8; i < 12; i++){
        printf("Opening file: %s\n", files[i]);

        // switching permissions to -> ---x--x--x
        chmod(files[i], S_IXUSR | S_IXGRP | S_IXOTH);
        f = fopen(files[i], "r");
        if (!f){
            fprintf(stderr, "Failed to open reading from file: %s\n", files[i]);
        }

        f = fopen(files[i], "w+");
        if (!f){
            fprintf(stderr, "Failed to open for writing to file: %s\n", files[i]);
            continue;
        }
        char testString[] = "testasfadsfafsdsdf";   // this should not be written
        fwrite(strdup(testString), 1, strlen(testString), f);
        fclose(f);
    }

    // mess with files 12, 13 5 times to show in the -i functionality
    for (int j = 12; j < 14; j++){
        for (int i = 0; i < 5; i++){
            f = fopen(files[j], "a");
            if (!f){
                fprintf(stderr, "Failed to open for append to file: %s\n", files[i]);
                continue;
            }
            char appendStr[] = "-append";                    // this should be appended 5 times
            fwrite(strdup(appendStr), 1, strlen(appendStr), f);
            fclose(f);
        }
    }
    

    free(files);
    return 0;
    
}

char ** makeFiles(int total_files, size_t file_size){
    char **listOfFiles = (char **)malloc(total_files*file_size);

    for (int i = 0; i < total_files; i++){
        char current_file[file_size];
        sprintf(current_file, "test_file_%d.txt", i);
        listOfFiles[i] = strdup(current_file);
    }

    return listOfFiles;
}