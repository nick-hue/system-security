#include <stdio.h>

int main(){
    printf("Calling the fopen() function for writing ...\n");

    FILE *f = fopen("write.txt", "w");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    printf("Successfully opened file.\n");
    return 0;
}