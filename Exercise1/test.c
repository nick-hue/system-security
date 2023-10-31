#include <stdio.h>
#include <gmp.h>

int main() {
    mpz_t largeInt;                  // Declare a GMP integer
    mpz_t reps;
    mpz_init(reps);
    mpz_init(largeInt);              // Initialize the integer
    mpz_set_str(reps, "10050", 10);
    
    // mpz_set_str(largeInt, "123456789012345678901234567890", 10); // Set the integer value using a string

    mpz_nextprime(largeInt, reps); 
    gmp_printf("Value: %Zd\n", largeInt); // Print the integer

    mpz_clear(largeInt);             // Clear the allocated memory for the integer
    return 0;
}
