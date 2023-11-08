#include <stdio.h>

int main(){
    printf("Calling the fopen() function for reading ...\n");

    FILE *f = fopen("test.txt", "r");
    if (!f){
        printf("Error: opening file\n");
        return 1;
    }
    printf("Successfully opened file.\n");
    return 0;
}