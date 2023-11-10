#include <stdio.h>

int main(){
    printf("Calling the fopen() function for WRITING ...\n");
    char str[] = "Hello World";

    FILE *f = fopen("write.txt", "w");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    fwrite(str, 1, sizeof(str) - 1, f);

    char str2[] = "Hello World234";

    FILE *f2 = fopen("write2.txt", "w");
    if (!f2){
        printf("Error: opening file\n");
        return 1;
    }
    fwrite(str2, 1, sizeof(str2) - 1, f2);
    fclose(f);
    fclose(f2);

    printf("Successfully opened file.\n");
    return 0;
}