#include <stdio.h>

int main(){
    printf("Calling the fopen() function for READING ...\n");

    char buffer[200];
    printf("reeree\n");
    FILE *f = fopen("test.txt", "r");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    
    fread(buffer, 1, 199, f);    // reading the contents of the file
    printf("Read from file: %s\n", buffer);
    printf("Successfully opened file.\n");
    fclose(f);
    return 0;
}