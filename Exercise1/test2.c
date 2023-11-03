#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

void read_two_mpz_from_file(const char *filename, mpz_t first) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Unable to open the file");
        exit(EXIT_FAILURE);
    }

    // Assuming the numbers are not excessively large, a fixed-size buffer is used
    char line[1024]; // Adjust the size as necessary for your numbers
    if (fgets(line, sizeof(line), file) == NULL) {
        printf("Failed to read the line from the file\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fclose(file);

    // Now use gmp_sscanf to parse the numbers from the line
    if (gmp_sscanf(line, "%Zd", first) != 1) {
        printf("Failed to parse two mpz_t numbers from the line\n");
        exit(EXIT_FAILURE);
    }
}

int main() {
    mpz_t first;
    mpz_init(first);

    // Call the function to read the numbers from file
    read_two_mpz_from_file("test.txt", first);

    // Print the numbers
    gmp_printf("The first number is: %Zd\n", first);

    // Clear mpz_t variables
    mpz_clear(first);

    return 0;
}
