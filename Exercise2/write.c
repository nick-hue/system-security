#include <stdio.h>

int main(){
    printf("Calling the fopen() function for writing ...\n");

    char str[] = "This is testing 123123132";

    FILE *f = fopen("write.txt", "w");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    printf("Successfully opened file.\n");
    
    fwrite(str, 1, sizeof(str)-1, f);
    fclose(f);

    return 0;
}