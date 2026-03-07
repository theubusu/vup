#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

int sign_data(
    const unsigned char *data,
    size_t data_len,
    const char *keyfile,
    unsigned char sig[128]
) {
    FILE *fp = fopen(keyfile, "r");
    if (!fp) return 0;

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha1(), NULL, pkey) <= 0)
        return 0;

    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0)
        return 0;

    size_t sig_len = 128;   // RSA1024 signature size

    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0)
        return 0;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return 1;
}