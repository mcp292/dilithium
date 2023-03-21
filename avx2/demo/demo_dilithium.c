/* Takes in action and depending on action takes in additional options as follows:
   if action == "generate":
     argument_list = ["generate", randomness/seed]
   elif action == "sign":
     argument_list = ["sign", private_key, message]
   elif action == "verify":
     argument_list = ["verify", public_key, message_hash] */

/* TODO: original demo broken after changing commandline arguments */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../randombytes.h"
#include "demo_sign.h"

#define MLEN 59

/* taken from https://github.com/mcp292/c_utils */
/** Convert hex string to byte array. [2.15.21]

    NOTE: Assumes hex string is of even length. No safety in place for array
    capacity. */
void hex_to_bytes(uint8_t bytes[], char *hex)
{
    int ind, hex_ind;
    unsigned int byte; /* %2x expects int. */

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

void parse_action(char action[], int argc, char *argv[], int action_ind)
{
    if (argc > action_ind)
    {
        memcpy(action, argv[action_ind], strlen(argv[action_ind]) + 1);
    }
    else
    {
        printf("Not enough arguments provided. Please provide an action "
               "argument!\n");
    }
}

void parse_message(
    uint8_t m[], size_t mlen, int argc, char *argv[], int message_ind)
{
    if (argc > message_ind)
    {
        memcpy(m, argv[message_ind], strlen(argv[message_ind]) + 1);
    }
    else
    {
        randombytes(m, mlen);
    }
}

void parse_random_bytes(
    uint8_t random_bytes[], size_t rblen, int argc, char *argv[],
    int random_bytes_ind)
{
    if (argc > random_bytes_ind)
    {
        assert((strlen(argv[random_bytes_ind]) / 2) == rblen);
        hex_to_bytes(random_bytes, argv[random_bytes_ind]);
    }
    else
    {
        randombytes(random_bytes, rblen);
    }
}

void parse_private_key(
    uint8_t sk[], int argc, char *argv[], int private_key_ind)
{
    if (argc > private_key_ind)
    {
        hex_to_bytes(sk, argv[private_key_ind]);
    }
    else
    {
        printf("Not enough arguments provided! Please provide the private key "
               "for signing!\n");
    }
}

void parse_public_key(
    uint8_t pk[], int argc, char *argv[], int public_key_ind)
{
    if (argc > public_key_ind)
    {
        hex_to_bytes(pk, argv[public_key_ind]);
    }
    else
    {
        printf("Not enough arguments provided! Please provide the public key "
               "for verification!\n");
    }
}

void parse_message_hash(
    uint8_t sm[], size_t *smlen, int argc, char *argv[], int message_hash_ind)
{
    if (argc > message_hash_ind)
    {
        hex_to_bytes(sm, argv[message_hash_ind]);
        *smlen = strlen(argv[message_hash_ind]) / 2;
    }
    else
    {
        printf("Not enough arguments provided! Please provide the message hash "
               "for verification!\n");
    }
}

int main(int argc, char *argv[])
{
    const int ACTION_IND = 1;
    const int ACTION_LEN = 80;

    const char *ACTION_GENERATE = "generate";
    const int RANDOM_BYTES_IND = 2;

    const char *ACTION_SIGN = "sign";
    const int PRIVATE_KEY_IND = 2;
    const int MESSAGE_IND = 3;

    const char *ACTION_VERIFY = "verify";
    const int PUBLIC_KEY_IND = 2;
    const int MESSAGE_HASH_IND = 3;

    int ret;
    size_t mlen, smlen;
    char action[ACTION_LEN];
    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES + 1];
    uint8_t sm[MLEN + CRYPTO_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t random_bytes[SEEDBYTES]; /* 256 */

    /* get action from cmd */
    parse_action(action, argc, argv, ACTION_IND);

    if (strcmp(action, ACTION_GENERATE) == 0)
    {
        /* parse randomness */
        parse_random_bytes(
            random_bytes, SEEDBYTES, argc, argv, RANDOM_BYTES_IND);

        /* generate pairs */
        demo_crypto_sign_keypair(random_bytes, pk, sk);

        /* print to cmdline */
        print_bytes_hex(pk, CRYPTO_PUBLICKEYBYTES);
        print_bytes_hex(sk, CRYPTO_SECRETKEYBYTES);
    }
    else if (strcmp(action, ACTION_SIGN) == 0)
    {
        /* parse private key */
        parse_private_key(sk, argc, argv, PRIVATE_KEY_IND);

        /* parse message */
        parse_message(m, MLEN, argc, argv, MESSAGE_IND);

        /* sign */
        crypto_sign(sm, &smlen, m, MLEN, sk);

        /* print to cmdline */
        print_bytes_hex(sm, smlen);
    }
    else if (strcmp(action, ACTION_VERIFY) == 0)
    {
        /* parse public key */
        parse_public_key(pk, argc, argv, PUBLIC_KEY_IND);

        /* parse message hash (extracting size) */
        parse_message_hash(sm, &smlen, argc, argv, MESSAGE_HASH_IND);

        /* verify */
        ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

        /* terminate m2 for printing */
        m2[mlen + 1] = '\0';

        /* dilithium error checks */
        if(ret) {
            printf("Failed\nVerification failed\n");
            return -1;
        }
        if(smlen != MLEN + CRYPTO_BYTES) {
            printf("Failed\nSigned message lengths wrong\n");
            return -1;
        }
        if(mlen != MLEN) {
            printf("Failed\nMessage lengths wrong\n");
            return -1;
        }

        /* print to cmdline */
        if (ret == 0) printf("Verified\n%s\n", m2);
    }

    return 0;
}
