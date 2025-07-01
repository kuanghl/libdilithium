#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign.h"
#include "b64.h"

int main(void)
{
    size_t siglen;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t *pk_b64 = NULL;
    uint8_t *sk_b64 = NULL;
    uint8_t *sig_b64 = NULL;
    uint8_t msg[32] = "Hello Word!";
    uint8_t msg_len = strlen((char*)msg);
    int ret = 0;

    // for encode base64
    pk_b64 = (uint8_t*)malloc(BASE64_ENCODE_OUT_SIZE(CRYPTO_PUBLICKEYBYTES));
    sk_b64 = (uint8_t*)malloc(BASE64_ENCODE_OUT_SIZE(CRYPTO_SECRETKEYBYTES));
    sig_b64 = (uint8_t*)malloc(BASE64_ENCODE_OUT_SIZE(CRYPTO_BYTES));

    printf("msg %s len %d\n", msg, msg_len);
    
    ret = crypto_sign_keypair(pk, sk);
    printf("Gen Keypair %d\n", ret);
    b64Encode((char*)pk, CRYPTO_PUBLICKEYBYTES, (char*)pk_b64);
    b64Encode((char*)sk, CRYPTO_SECRETKEYBYTES, (char*)sk_b64);
    printf("pk=%s\n", pk_b64);
    printf("sk=%s\n", sk_b64);

    ret = crypto_sign_signature(sig, &siglen, msg, msg_len, NULL, 0, sk);
    printf("Sign %d len %ld\n", ret, siglen);
    b64Encode((char*)sig, CRYPTO_BYTES, (char*)sig_b64);
    printf("sig=%s\n", sig_b64);

    ret = crypto_sign_verify(sig, CRYPTO_BYTES, msg, msg_len, NULL, 0, pk);
    printf("Verify %d\n", ret);

    // free
    free(pk_b64);
    free(sk_b64);
    free(sig_b64);

    return 0;
}