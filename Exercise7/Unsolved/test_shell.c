#include <stdio.h>
#include <string.h>

char shellcode[] = ;


int main(int argc, char ** argv)
{
    void (*shell)() = (void *)&shellcode;
    shell();


    return 0;
}