#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <gmp.h>
#include <time.h>

void showArgs(char *inputFile, char * outputFile, char *keyFile, int keyLength, char * mode);
void generateRSAKeyPair(int length, int p, int q);
void writeKeyToFile(char* filename, int key, int keyLength);
int lambda(int p, int q);
mpz_t getRandomPrime();


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
        fprintf(stderr, "Error: while in encrypt/decrypt mode you need the [i],[o],[k] arguments.\nUse -h flag to show more info about arguments.\n");
        exit(EXIT_FAILURE);
    }

    if (mode == "compare"){
        for (int i=0; i<3;i++){

        }
    }


    generateRSAKeyPair(keyLength, 17, 11);

    return 0;
}

void writeKeyToFile(char* filename, int key, int keyLength){
    FILE *f = fopen(filename, "w");
    char fileOutput[keyLength]; 
    sprintf(fileOutput, "<%d>", key);
    fprintf(f, fileOutput);
    printf("Wrote to file: %s\n", filename);
    fclose(f);
    printf("Closed file: %s\n", filename);
}

mpz_t getRandomPrime(){
    srand(time(NULL));   // Initialization, should only be called once.
    int r = rand();      // Returns a pseudo-random integer between 0 and RAND_MAX.
    return;
}


void generateRSAKeyPair(int length, int p, int q){
    int n,e; 
    n = p*q;
    
    char *publicPath = "public_length.key";
    char *privatePath = "private_length.key";



    writeKeyToFile(publicPath, 13414234, length);
    writeKeyToFile(privatePath, 5656565, length);
}

int lambda(int p, int q){
    return (p-1)*(q-1);
}

void showArgs(char *inputFile, char * outputFile, char *keyFile, int keyLength, char * mode){
    printf("Input File: %s\n", inputFile);
    printf("Output File: %s\n", outputFile);
    printf("Key File: %s\n", keyFile);
    printf("Key Length = %d\n", keyLength);
    printf("Mode = %s\n", mode);
}