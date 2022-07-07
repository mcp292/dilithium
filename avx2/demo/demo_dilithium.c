#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../randombytes.h"
#include "demo_sign.h"

#define MLEN 59

/* takes in message and random_bytes as commandline arguments, in that order */
#define MESSAGE_IND 1
#define RANDOM_BYTES_IND 2

/* taken from https://github.com/mcp292/c_utils */
/** Convert hex string to byte array. [2.15.21]

    NOTE: Assumes hex string is of even length. No safety in place for array
    capacity. */
void hex_to_bytes(uint8_t bytes[], char *hex)
{
    int ind, hex_ind, byte; /* %2x expects int. */

    for (ind = hex_ind = 0;
         hex[hex_ind] != '\0';
         ind++, hex_ind += 2)
    {
        sscanf(&hex[hex_ind], "%2x", &byte);
        bytes[ind] = byte;
    }
}

/** \brief Displays byte array in hex form. */
void print_bytes_hex(uint8_t bytes[], int size)
{
    int ind;

    for (ind = 0; ind < size; ind++)
    {
        printf("%.2x", bytes[ind]);
    }
    printf("\n");
}


void parse_message(uint8_t m[], size_t mlen, int argc, char *argv[])
{
    if (argc > MESSAGE_IND)
    {
        memcpy(m, argv[MESSAGE_IND], strlen(argv[MESSAGE_IND]) + 1);
    }
    else
    {
        randombytes(m, mlen);
    }

    printf("Message: %s\n", m);
}

void parse_random_bytes(uint8_t random_bytes[], size_t rblen, int argc, char *argv[])
{
    size_t ind;

    if (argc > RANDOM_BYTES_IND)
    {
        assert((strlen(argv[RANDOM_BYTES_IND]) / 2) == rblen);
        hex_to_bytes(random_bytes, argv[RANDOM_BYTES_IND]);
    }
    else
    {
        randombytes(random_bytes, rblen);
    }

    printf("Randomness: ");
    print_bytes_hex(random_bytes, rblen);
    printf("\n");
}

int main(int argc, char *argv[])
{
    size_t i;
    int ret;
    size_t mlen, smlen;
    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t random_bytes[SEEDBYTES]; /* 256 */

    /* take message from cmd */
    /* convert to bytes? */
    /* temp */
    /* randombytes(m, MLEN); */
    /* randombytes(random_bytes, SEEDBYTES); */
    parse_message(m, MLEN, argc, argv);
    parse_random_bytes(random_bytes, SEEDBYTES, argc, argv);
    /* temp */

    /* pass random puf data to function from cmd */

    /* generate keypairs, sign, verify */
    demo_crypto_sign_keypair(random_bytes, pk, sk);
    crypto_sign(sm, &smlen, m, MLEN, sk);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    /* terminate m2 for printing */
    m2[mlen + 1] = '\0';

    if(ret) {
        fprintf(stderr, "Verification failed\n");
        return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES) {
        fprintf(stderr, "Signed message lengths wrong\n");
        return -1;
    }
    if(mlen != MLEN) {
        fprintf(stderr, "Message lengths wrong\n");
        return -1;
    }
    for(i = 0; i < MLEN; ++i) {
        if(m2[i] != m[i]) {
            fprintf(stderr, "Messages don't match\n");
            return -1;
        }
    }

    printf("Public key bytes: %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("Secret key bytes: %d\n", CRYPTO_SECRETKEYBYTES);
    printf("Crypto bytes: %d\n", CRYPTO_BYTES);

    printf("\nPublic key:\n");
    print_bytes_hex(pk, CRYPTO_PUBLICKEYBYTES);

    printf("\nSecret key:\n");
    print_bytes_hex(sk, CRYPTO_SECRETKEYBYTES);

    printf("\nSignature:\n");
    print_bytes_hex(sm, smlen);

    if (ret == 0) printf("\nMessage verified successfully!\n");
    printf("Opened message: %s\n", m2);

    return 0;
}
