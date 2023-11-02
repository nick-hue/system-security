#include <stdio.h>
#include <gmp.h>

int main() {
    mpz_t p,q,e,n,d,m,c,result;                  // Declare a GMP integer
    mpz_inits(p,q,e,n,d,m,c,result, NULL);
    
    mpz_set_str(m, "42", 10);
    mpz_set_str(p, "61", 10);
    mpz_set_str(q, "53", 10);
    mpz_set_str(e, "17", 10);
    mpz_set_str(n, "3233", 10);
    mpz_set_str(d, "2753", 10);
    
    gmp_printf("Plain text: %Zd\n", m); 
    mpz_powm(c,m,e,n);
    gmp_printf("Encrypted: %Zd\n", c); 
    mpz_powm(result,c,d,n);
    gmp_printf("Decrypted: %Zd\n", result); 

    mpz_clears(p,q,e,n,d,m,c,result, NULL);
    return 0;
}
