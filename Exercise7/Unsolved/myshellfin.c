#include <stdio.h>
#include <stdlib.h>

void main (){
    char* shell = getenv("SHELL");
    if (shell) {
        printf("%x\n", (unsigned int) shell);
    }
}