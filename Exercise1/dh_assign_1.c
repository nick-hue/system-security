#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <gmp.h>

void showArgs(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b);
void dh_algorithm(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b);
int checkSharedSecret(mpz_t p, mpz_t secret);

int main(int argc, char *argv[]) {
    int opt;
    char *outputFile = NULL;
    int h = 0;
    mpz_t p, g, a, b;
    mpz_inits(p, g, a, b, NULL);
    
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

    // checks if [-p] argument is prime, if not throw error // mpz_probab_prime_p: returns 2 if definitely prime, 1 if probably prime, 0 if not prime
    // we put 30 as reps argument, documentation suggests between 15 and 50 (higher the rep, lower the possibility of mistake)
    if (mpz_probab_prime_p(p, 30) == 0){
        fprintf(stderr, "Argument [-p] is not prime number.\nUse -h flag to show more info about arguments.\n");
        exit(EXIT_FAILURE);
    }

    // ensure a<p or b<p
    if ((mpz_cmp(p,a) < 0) || (mpz_cmp(p,b) < 0)){
        fprintf(stderr, "Arguments [-a], [-b] have to be smaller than argument [-p].\nUse -h flag to show more info about arguments.\n");
        exit(EXIT_FAILURE);
    }

    // print given arguments to the console
    showArgs(outputFile, p, g, a, b);
    
    // if one of the command line flags are not given correctly, exit the program
    if (outputFile==NULL || p==NULL || g==NULL || a==NULL || b==NULL){
        fprintf(stderr, "Error invalid arguments given.\nUse -h flag to show more info about arguments.\n");
        exit(EXIT_FAILURE);
    }

    // writes to the output file the <public key A>, <public key B>, <shared secret> computed from the Diffie-Hellman Algorithm 
    dh_algorithm(outputFile, p, g, a, b);

    // clear variables
    mpz_clears(p,g,a,b);

    return 0;
}

void showArgs(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b) {
    printf("Output File: %s\n", outputFile);
    gmp_printf("p = %Zd\n", p);
    gmp_printf("g = %Zd\n", g);
    gmp_printf("a = %Zd\n", a);
    gmp_printf("b = %Zd\n", b);
}

int checkSharedSecret(mpz_t p, mpz_t secret){
    // 1 < secret < p-1
    // mpz_cmp: Compare op1 and op2. Return a positive value if op1 > op2, zero if op1 = op2, or a negative value if op1 < op2.

    mpz_t p_1;
    mpz_init(p_1);
    mpz_sub_ui(p_1, p, 1); // Calculate p-1

    if ((mpz_cmp_d(secret, 1) > 0) && (mpz_cmp(p_1, secret) > 0)){
        mpz_clear(p_1);
        return 0; // true
    } else {
        mpz_clear(p_1);
        return 1; // false
    }
}

void dh_algorithm(char *outputFile, mpz_t p, mpz_t g, mpz_t a, mpz_t b){
    mpz_t publicA, publicB, secret;
    mpz_inits(publicA, publicB, secret, NULL);

    // void mpz_powm (mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod)
    // Set rop to (base raised to exp) modulo mod.
    mpz_powm(publicA, g, a, p);             // publicA = (g^a) mod p 
    mpz_powm(publicB, g, b, p);             // publicB = (g^b) mod p

    mpz_powm(secret, publicA, b, p);        // Bob's side   s = (publicA^b) mod p
    // mpz_powm(secret, publicB, a, p);     // Alice's side s = (publicB^a) mod p

    FILE *f = fopen(outputFile, "w");
    
    // making the string lengths for each variable
    size_t lenA = mpz_sizeinbase(publicA, 10) + 1;  // +1 for null terminator
    size_t lenB = mpz_sizeinbase(publicB, 10) + 1;
    size_t lenS = mpz_sizeinbase(secret, 10) + 1;

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

    // test prints
    /*
    gmp_printf("\nOUTPUT\npublicA = %s\n", publicA_str);
    gmp_printf("publicB = %s\n", publicB_str);
    gmp_printf("secret = %s\n", secret_str);
    // checking if error message would work
    mpz_set_str(secret, "65165465465464", 10);
    */ 

    // before writing to file check whether shared secret is 1 < secret < p-1 
    if (checkSharedSecret(p, secret) == 1){
        fprintf(stderr, "Shared secret was not between 1 and p-1.\n");
        exit(EXIT_FAILURE);
    }

    // writing to file
    sprintf(fileOutput, "<%s>, <%s>, <%s>", publicA_str, publicB_str, secret_str);
    fprintf(f, fileOutput);
    fclose(f);

    // clearing memory
    mpz_clears(publicA,publicB, secret);
}

//hello!!!!!!!!!!!