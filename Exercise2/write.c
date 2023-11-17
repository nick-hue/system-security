#include <stdio.h>

int main(){
    printf("Calling the fopen() function for WRITING ...\n");
    char str[] = "Hello World13123123132";

    FILE *f = fopen("write.txt", "a");
    FILE *f2 = fopen("write2.txt", "a");

    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
   

    if (!f2){
        printf("Error: opening file\n");
        return 1;
    }
    fwrite(str, 1, sizeof(str) - 1, f2);
    fwrite(str, 1, sizeof(str) - 1, f);
    fclose(f);
    fclose(f2);

    f = fopen("write.txt", "a");
    fwrite(str, 1, sizeof(str) - 1, f);
    fclose(f);

    printf("Successfully opened file.\n");
    return 0;
}