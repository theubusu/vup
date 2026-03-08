#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

int signDataRSA1024(
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

int verifyDataRSA1024(
    const unsigned char *data,
    size_t data_len,
    const unsigned char *sig,
    size_t sig_len,
    const char *pubkey_file
) {
    FILE *fp = fopen(pubkey_file, "r");
    if (!fp) return -1;

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha1(), NULL, pkey) <= 0)
        return -1;

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0)
        return -1;

    int result = EVP_DigestVerifyFinal(ctx, sig, sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result;
}