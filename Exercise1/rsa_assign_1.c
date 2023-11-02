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
void makeMeasurements(char *outputFile);
void encryptFile(char *inputFile, char *outputFile, char * keyFile);
void readKeysFromFile(const char *filename, mpz_t first, mpz_t second);
void encode(mpz_t result, mpz_t m, mpz_t n);
size_t getSizeOfFile(FILE *file);
unsigned char* getRandomNonZeroBytes(size_t length);

int main(int argc, char *argv[]) {
    int opt;
    char *outputFile = NULL, *inputFile = NULL, *keyFile = NULL, *mode = NULL;
    int keyLength = 0 , h = 0;

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
                makeMeasurements(outputFile);
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
    encryptFile(inputFile, outputFile, keyFile);

    return 0;
}  

void generateRSAKeyPair(int length){
    mpz_t p, q, n, e, d, phi, check_e, check_gcd;
    mpz_inits(p, q, n, e, d, phi, check_e, check_gcd, NULL);

    generateRandomPrime(p, length);
    generateRandomPrime(q, length);

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

    char publicPath[20]; 
    sprintf(publicPath, "public_%d.key", length);

    char privatePath[20];
    sprintf(privatePath, "private_%d.key", length);

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

    if (f == NULL) {
        fprintf(stderr, "Error: failed to open file -> %s\n", filename);
        exit(EXIT_FAILURE);
    }
    
    sprintf(resultString, "%s,%s", str1, str2);
    fprintf(f, "%s", resultString);

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

void makeMeasurements(char *outputFile){
    int sizes[3] = {1024, 2048, 4096};
    char measumentsString[1024];

    for (int i = 0; i < 3; i++){
        printf(" -- Making keys for size: %d\n", sizes[i]);
        
        clock_t begin = clock();
        generateRSAKeyPair(sizes[i]);
        // ** ENCRYPT AND DECRYPT FILES
        
        clock_t end = clock();
        double time_spent = (double)(end - begin) / CLOCKS_PER_SEC; // dividing by CLOCKS_PER_SEC(1000) to get the time in seconds.
        char currentString[40];
        sprintf(currentString, "Measurements for %d: %lf seconds\n", sizes[i], time_spent);
        strcat(measumentsString, currentString);
    }
    // write the measuremebts to file
    FILE *f = fopen(outputFile, "w");

    // check if file opened correctly
    if (f == NULL) {
        fprintf(stderr, "Error: failed to open file -> %s\n", outputFile);
        exit(EXIT_FAILURE);
    }    
    
    fprintf(f, "%s", measumentsString);
    printf("Wrote to file: %s\n", outputFile);
    fclose(f);
    printf("Closed file:   %s\n", outputFile);
    
}

void encryptFile(char *inputFile, char *outputFile, char *keyFile){

    mpz_t n, e;
    mpz_inits(n, e, NULL);
    
    FILE *fin = fopen(inputFile, "r");
    FILE *fout = fopen(outputFile, "w");

    // check if file opened correctly
    if (fin == NULL || fout == NULL) {
        fprintf(stderr, "Error: failed to open file -> %s\n", inputFile);
        exit(EXIT_FAILURE);
    }
    readKeysFromFile(keyFile, n, e);
    gmp_printf("The n: %Zd\n", n);
    gmp_printf("The e: %Zd\n", e);

    char ch;
    mpz_t currentBlock, cypher, encodedBlock;
    mpz_inits(currentBlock, cypher, encodedBlock, n, e, NULL);      
    do {
        ch = fgetc(fin);
        printf("%c = %d\n", ch, (int)ch);
        mpz_set_si(currentBlock, (int)ch); // Set the mpz_t to the integer value
        gmp_printf("MPZ INT: %Zd\n", currentBlock); 
        encode(encodedBlock, currentBlock, n); // adds the padding to the current block 
        mpz_powm(cypher,encodedBlock,e,n);
        gmp_printf("CIPHER: %Zd\n", cypher); 

    } while (ch != EOF);

  
    
    // closing input file
    fclose(fin);
    mpz_clears(currentBlock, cypher, encodedBlock, n, e, NULL);
}

void encode(mpz_t result, mpz_t m, mpz_t n){
    size_t kLen = 0; 
    void *p = mpz_export(NULL, &kLen, 1, sizeof(char), 0, 0, n);
    unsigned char *n_bytes = malloc(kLen);  
    memcpy(n_bytes, p, kLen);               
    free(p);                                

    printf("kLen = %d\nBytes: ", kLen);
    for (int i = 0; i<kLen; i++){
        printf("%02X ", n_bytes[i]);
    }

    size_t dLen = 0; 
    p = mpz_export(NULL, &dLen, 1, sizeof(char), 0, 0, m);
    unsigned char *message_bytes = malloc(dLen);  
    memcpy(message_bytes, p, dLen);             
    free(p);

    printf("dLen = %d\nBytes: ", dLen);
    for (int i = 0; i<dLen; i++){
        printf("%02X", message_bytes[i]);
    }

    if (dLen <= kLen-11){
        fprintf(stderr, "Not Right size for padding.");
        exit(EXIT_FAILURE);
    }
    size_t rLen = (kLen - dLen - 3);

    unsigned char *randBytes = getRandomNonZeroBytes(rLen);

    size_t resultLen = rLen + dLen + 3; // 3 + 1?
    unsigned char *resultBytes = malloc(resultLen);;
    resultBytes[0] = 0x00;
    resultBytes[1] = 0x02;
    memcpy(resultBytes + 2, randBytes, rLen);
    resultBytes[rLen+2] = 0x00;
    memcpy(resultBytes + rLen + 3, message_bytes, dLen);

    mpz_import(result,resultLen,1,sizeof(resultBytes[0]),0,0,resultBytes);
    free(n_bytes);
    free(message_bytes);
    free(randBytes);
    free(resultBytes);
}

unsigned char* getRandomNonZeroBytes(size_t length){
    unsigned char* bytes = malloc(length);
    if (bytes == NULL) {
        fprintf(stderr, "Failed memory allocation.");
        exit(EXIT_FAILURE);
    }

    // Seed the random number generator
    srand(time(NULL));

    for (size_t i = 0; i < length; ++i) {
        do {
            bytes[i] = (unsigned char)(rand() % 256);
        } while (bytes[i] == 0); // Ensure the byte is not zero
    }

    return bytes;
}

void readKeysFromFile(const char *filename, mpz_t first, mpz_t second){
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Unable to open the file");
        exit(EXIT_FAILURE);
    }

    // Size of the buffer is length/8  //// CHANGES
    char buffer[1024];

    // fill the buffer with the file componenets
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        printf("Failed to read the line from the file\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // parse the keys from the buffer, show to the gmp_sscanf that the format is "n,e"
    if (gmp_sscanf(buffer, "%Zd,%Zd", first, second) != 2) {
        printf("Failed to parse two mpz_t numbers from the line\n");
        exit(EXIT_FAILURE);
    }

    // close the key file
    fclose(file);

}

size_t getSizeOfFile(FILE *file){ // file has to be already opened 
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    return size;
}
    

void showArgs(char *inputFile, char * outputFile, char *keyFile, int keyLength, char * mode){
    printf("Input File: %s\n", inputFile);
    printf("Output File: %s\n", outputFile);
    printf("Key File: %s\n", keyFile);
    printf("Key Length = %d\n", keyLength);
    printf("Mode = %s\n", mode);
}