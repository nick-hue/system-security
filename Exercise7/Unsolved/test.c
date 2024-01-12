#include <stdio.h>

void get_shell(){
    char *args[2];
    args[0] = "/bin/bash";
    args[1] = NULL;
    execve(args[0], args, NULL);
    return;
}

int main(){

    get_shell();

    return 0;
}