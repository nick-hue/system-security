#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <gmp.h>

void showArgs(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b);
void dh_algorithm(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b);

int main(int argc, char *argv[]) {
    int opt;
    char *outputFile = NULL;
    mpz_t p, g, a, b;
    int h = 0; 
    mpz_init(p);
    mpz_init(g);
    mpz_init(a);
    mpz_init(b);

    
    while ((opt = getopt(argc, argv, "o:p:g:a:b:h")) != -1) {
        switch (opt) {
            case 'o':
                outputFile = optarg; // getopt sets the optarg variable to point to the argument following -o, the string "output.txt".
                break;
            case 'p':
                mpz_set_str(p, optarg, 10);
                break;
            case 'g':
                mpz_set_str(g, optarg, 10);
                break;
            case 'a':
                mpz_set_str(a, optarg, 10);
                break;
            case 'b':
                mpz_set_str(b, optarg, 10);
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

    // clear variables
    mpz_clear(p);
    mpz_clear(g);
    mpz_clear(a);
    mpz_clear(b);

    return 0;
}

void showArgs(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b) {
    printf("Output File: %s\n", outputFile);
    gmp_printf("p = %Zd\n", p);
    gmp_printf("g = %Zd\n", g);
    gmp_printf("a = %Zd\n", a);
    gmp_printf("b = %Zd\n", b);
}

void dh_algorithm(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b){
    mpz_t publicA, publicB, secret;
    mpz_init(publicA);
    mpz_init(publicB);
    mpz_init(secret);

    mpz_powm(publicA, g, b, p);
    mpz_powm(publicB, g, b, p);

    mpz_powm(secret, publicA, b, p);        // Bob's side 
    // mpz_powm(secret, publicB, a, p);     // Alice's side

    FILE *f = fopen(outputFile, "w");
    
    size_t lenA = mpz_sizeinbase(publicA, 10) + 2;  // +2 for null terminator, potential '-' sign
    size_t lenB = mpz_sizeinbase(publicB, 10) + 2;
    size_t lenS = mpz_sizeinbase(secret, 10) + 2;

    // initializing the buffer for writing into the file
    char fileOutput[lenA+lenB+lenS]; // buffer size for publicA_size + publicB_size + secret

    // making a string for publicA and putting it's content in 
    char publicA_str[lenA];
    mpz_get_str(publicA_str, 10, publicA);
    
    // making a string for publicB and putting it's content in 
    char publicB_str[lenB];
    mpz_get_str(publicB_str, 10, publicB);

    // making a string for secret and putting it's content in 
    char secret_str[lenS];
    mpz_get_str(secret_str, 10, secret);

    gmp_printf("\nOUTPUT\npublicA = %s\n", publicA_str);
    gmp_printf("publicB = %s\n", publicB_str);
    gmp_printf("secret = %s\n", secret_str);

    sprintf(fileOutput, "<%s>, <%s>, <%s>", publicA_str, publicB_str, secret_str);
    fprintf(f, fileOutput);
    fclose(f);

    mpz_clear(publicA);
    mpz_clear(publicB);
    mpz_clear(secret);
}