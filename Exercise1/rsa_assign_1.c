#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <gmp.h>
#include <time.h>

void showArgs(char *inputFile, char * outputFile, char *keyFile, int keyLength, char * mode);
void generateRSAKeyPair(int length);
void writeKeyToFile(const char* filename, const char* n_str, const char* d_str, const size_t buffer_size);
void generateRandomPrime(mpz_t result, int num_bits);
void lambda(mpz_t result, mpz_t p, mpz_t q);

int main(int argc, char *argv[]) {
    int opt;
    char *outputFile = NULL, *inputFile = NULL, *keyFile = NULL, *mode = NULL;
    int keyLength = 0 , h = 0;
    int sizes[3] = {1024, 2048, 4096};

    while ((opt = getopt(argc, argv, "i:o:k:g:a:deh")) != -1) {
        switch (opt) {
            case 'i':
                inputFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            case 'k':
                keyFile = optarg;
                break;
            case 'g':
                keyLength = atoi(optarg);
                generateRSAKeyPair(keyLength);
                break;
            case 'd':
                mode = "decrypt";
                break;
            case 'e':
                mode = "encrypt";
                break;
            case 'a':
                mode = "compare";
                outputFile = optarg;
                break;
            case 'h':
                h = 1;
                break;
            default:
                fprintf(stderr, "Error invalid arguments given.\nUse -h flag to show more info about arguments.\nHEREERRE");
                exit(EXIT_FAILURE);
        }
    }

    if (h == 1){
        printf("-> The arguments [-i], [-o] and [-k] are always required when using [-e] or [-d]\n-> Using -i and a path the user specifies the path to the input file.\n-> Using -o and a path the user specifies the path to the output file.\n-> Using -k and a path the user specifies the path to the key file.\n-> Using -g the tool generates a public and a private key given a key length [length] and stores them to the public_length.key and private_length.key files respectively.\n-> Using -d the user specifies that the tool should read the ciphertext from the input file, decrypt it and then store the plaintext in the output file.\n-> Using -e the user specifies that the tool should read the plaintext from the input file, encrypt it and store the ciphertext in the output file.\n-> Using -a the user generates three distinct sets of public and private key pairs, allowing for a comparison of the encryption and decryption times for each.");
        return 1;
    }
        
    showArgs(inputFile, outputFile, keyFile, keyLength, mode);
    
    /* if mode is either encrypt or decrypt and we don't have a input, output, keyFile path produce an error message. */
    if ((mode=="encrypt" || mode=="decrypt") && (inputFile==NULL || outputFile==NULL || keyFile==NULL)){
        fprintf(stderr, "Error: while in encrypt[-e]/decrypt[-d] mode you need the [-i],[-o],[-k] arguments.\nUse -h flag to show more info about arguments.\n");
        exit(EXIT_FAILURE);
    }



    return 0;
}  

void generateRSAKeyPair(int length){
    mpz_t p, q, n, e, d, phi, check_e, check_gcd;
    mpz_inits(p, q, n, e, d, phi, check_e, check_gcd, NULL);
    generateRandomPrime(p, 1024);
    generateRandomPrime(q, 1024);

    gmp_printf("p = %Zd\n", p);
    gmp_printf("q = %Zd\n", q);

    // check if generated numbers are 
    if ((mpz_probab_prime_p(p, 30) == 0) || (mpz_probab_prime_p(q, 30) == 0) ){
        fprintf(stderr, "Generated number [p]/[q] is not prime number.\n");
        exit(EXIT_FAILURE);
    }
    printf("PRIME\n");

    mpz_mul(n,p,q);   // n = p * q 

    lambda(phi, p, q); // phi = lambda(n) = (p - 1) * (q - 1)
    printf("HERE\n");

    //  (e % lambda(n) != 0) AND (gcd(e, lambda) == 1) 
    do {
        generateRandomPrime(e, 1024);   // e
        mpz_mod(check_e, e, phi);       // e % lambda(n)
        mpz_gcd(check_gcd, e, phi);     // gcd(e, lambda)
    } while(!(mpz_cmp_d(check_e,0) > 0 && mpz_cmp_d(check_gcd,1)==0));
    //  int mpz_cmp_d (const mpz_t op1, double op2)
    // while(check_e == 0 || check_gcd!=1);

    mpz_invert(d, e, phi);

    char *publicPath = "public_length.key";
    char *privatePath = "private_length.key";

    size_t lenN = mpz_sizeinbase(n, 2) + 1;
    size_t lenD = mpz_sizeinbase(d, 2) + 1;
    size_t lenE = mpz_sizeinbase(e, 2) + 1;
    
    char n_str[lenN];
    mpz_get_str(n_str, 2, n);
    
    char d_str[lenD];
    mpz_get_str(d_str, 2, d);

    char e_str[lenN];
    mpz_get_str(e_str, 2, e);

    // The public key consists of n and d, in this order.
    // The private key consists of n and e, in this order

    writeKeyToFile(publicPath, n_str, d_str, lenN+lenD);    // write to public file n, d
    writeKeyToFile(privatePath, n_str, e_str, lenN+lenE);   // write to private file n, e

    mpz_clears(p, q, n, e, d, phi, check_e, check_gcd, NULL);
}

void writeKeyToFile(const char* filename, const char* str1, const char* str2, const size_t buffer_size){
    char resultString[buffer_size];
    FILE *f = fopen(filename, "w");

    sprintf(resultString, "%s,%s", str1, str2);
    fprintf(f, resultString);

    printf("Wrote to file: %s\n", filename);
    fclose(f);
    printf("Closed file:   %s\n", filename);
}

void lambda(mpz_t result, mpz_t p, mpz_t q){
    mpz_t p_1, q_1;
    mpz_inits(p_1, q_1, NULL);
    mpz_sub_ui(p_1, p, 1); // Calculate p-1
    mpz_sub_ui(q_1, q, 1); // Calculate q-1
    
    mpz_mul(result,p,q);   // n = p * q 

    mpz_clears(p_1, q_1, NULL);
}

void generateRandomPrime(mpz_t result, int length){
    gmp_randstate_t state;

    // Initialize random state
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL)); // Seed with current time

    do {
        mpz_urandomb(result, state, length/2);                  // Generate a random number with length bits
        mpz_nextprime(result, result);                          // Get the next prime after the random number we chose
    } while (mpz_sizeinbase(result, 2) > length/2);             // Ensure it doesn't exceed the specified number of bits


    // Clear random state
    gmp_randclear(state);  
}

void showArgs(char *inputFile, char * outputFile, char *keyFile, int keyLength, char * mode){
    printf("Input File: %s\n", inputFile);
    printf("Output File: %s\n", outputFile);
    printf("Key File: %s\n", keyFile);
    printf("Key Length = %d\n", keyLength);
    printf("Mode = %s\n", mode);
}