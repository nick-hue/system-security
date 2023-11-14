#include <stdio.h>

int main(){
    printf("Calling the fopen() function for WRITING ...\n");
    char str[] = "Hello World13123123132";

    FILE *f = fopen("write.txt", "a");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    fwrite(str, 1, sizeof(str) - 1, f);
    fclose(f);

    printf("Successfully opened file.\n");
    return 0;
}