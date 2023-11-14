#include <stdio.h>
#include <stdlib.h>

int main(){
    printf("Calling the fopen() function for READING ...\n");

    FILE *f = fopen("test.txt", "r");
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    char *buffer = (char *)malloc(size);

    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    
    fread(buffer, 1, size, f);    // reading the contents of the file
    printf("Read from file: %s\n", buffer);
    printf("Successfully opened file.\n");
    
    free(buffer);
    fclose(f);
    return 0;
}