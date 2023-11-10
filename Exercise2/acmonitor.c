#include <stdio.h>

int main(){
    printf("Calling the fopen() function for WRITING ...\n");
    char str[] = "Hello World13123123132";

    FILE *f = fopen("file_logging.log", "r");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    


    fclose(f);

    printf("Successfully opened file.\n");
    return 0;
}