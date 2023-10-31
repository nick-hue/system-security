#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
// NIKOLOKOS
void showArgs(char *outputFile, int p, int g, int a, int b);
void dh_algorithm(char *outputFile, unsigned long long p, unsigned long long g, unsigned long long a, unsigned long long b);

int main(int argc, char *argv[]) {
    int opt;
    char *outputFile = NULL;
    unsigned long long p = 0, g = 0, a = 0, b = 0, h = 0;

    while ((opt = getopt(argc, argv, "o:p:g:a:b:h")) != -1) {
        switch (opt) {
            case 'o':
                outputFile = optarg; // getopt sets the optarg variable to point to the argument following -o, the string "output.txt".
                break;
            case 'p':
                p = atoi(optarg);
                break;
            case 'g':
                g = atoi(optarg);
                break;
            case 'a':
                a = atoi(optarg);
                break;
            case 'b':
                b = atoi(optarg);
                break;
            case 'h':
                h = 1;
                break;
            default:
                fprintf(stderr, "Error invalid arguments given.\nUse -h flag to show more info about arguments.\n");
                exit(EXIT_FAILURE);
        }
    }

    if (h == 1){
        printf("-> [-o Path to output file]\n-> [-p Prime number]\n-> [-g Primitive Root for previous prime number]\n-> [-a Private A key]\n-> [-b Private B key]\n");
        return 1;
    }
        
    showArgs(outputFile, p, g, a, b);
    
    /* if one of the command line flags are not given correctly, exit the program */
    if (outputFile==NULL || p==0 || g==0 || a==0 || b == 0){
        fprintf(stderr, "Error invalid arguments given.\nUse -h flag to show more info about arguments.\n");
        exit(EXIT_FAILURE);
    }

    /* writes to the output file the <public key A>, <public key B>, <shared secret> computed from the Diffie-Hellman Algorithm */ 
    dh_algorithm(outputFile, p, g, a, b);

    return 0;
}

void showArgs(char *outputFile, int p, int g, int a, int b){
    printf("Output File: %s\n", outputFile);
    printf("p = %d\n", p);
    printf("g = %d\n", g);
    printf("a = %d\n", a);
    printf("b = %d\n", b);
}

void dh_algorithm(char *outputFile, unsigned long long p, unsigned long long g, unsigned long long a, unsigned long long b){
    unsigned long long publicA, publicB, secret;

    publicA = fmod(pow(g,a), p);
    publicB = fmod(pow(g,b), p);

    secret = fmod(pow(publicA, b), p); // Bob's side 
    // secret = fmod(power(publicB, a), p); // Alice's side

    FILE *f = fopen(outputFile, "w");
    char fileOutput[40]; // buffer size is 40 because we have a maximum of 10 characters per integer -> 3x10->30 characters and 10 characters for the '<', ',', '>' and '\0'
    sprintf(fileOutput, "<%d>, <%d>, <%d>", (int)publicA, (int)publicB, (int)secret);
    fprintf(f, fileOutput);
    fclose(f);
}