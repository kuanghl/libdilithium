#include <stdint.h>
#include <string.h>
#include "sign.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 1000

uint64_t t[NTESTS];

int main(void)
{
    unsigned int i;
    size_t siglen;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t msg[32] = "Hello Word!";
    uint8_t msg_len = strlen((char*)msg);

    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_sign_keypair(pk, sk);
    }
    print_results("Keypair:", t, NTESTS);

    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_sign_signature(sig, &siglen, msg, msg_len, NULL, 0, sk);
    }
    print_results("Sign:", t, NTESTS);

    for(i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        crypto_sign_verify(sig, CRYPTO_BYTES, msg, msg_len, NULL, 0, pk);
    }
    print_results("Verify:", t, NTESTS);

    return 0;
}
