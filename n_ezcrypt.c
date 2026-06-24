/* EZcrypt */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* define */
#define MODE_ENCRYPT 0
#define MODE_DECRYPT 1

/* crypt function prototype */
int bufEncrypt(unsigned char *buf, size_t buf_len, unsigned char key[8], unsigned char iv[8]);
int bufDecrypt(unsigned char *buf, size_t buf_len, unsigned char key[8], unsigned char iv[8]);

/* utility: decode hex string to array*/
void decodeHexString(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%2hhx", &out[i]);
    }
}

/* program interface */
int main(int argc, char *argv[]) {
	printf("EZcrypt v1.0\n");

    if (argc < 6) {
        printf("[ERR] not enough arguments\n");
        printf("usage: ezcrypt <mode> <key> <iv> <input file> <output file>\n");
        printf("<mode>: e = encrypt, d = decrypt\n");
        return 1;
    }

    int mode;
    char *modeStr = argv[1];
    printf("modeStr=%s\n", modeStr);
    if (memcmp(modeStr, "e", 1) == 0) {
        printf("mode=MODE_ENCRYPT\n");
        mode = MODE_ENCRYPT;
    } else if (memcmp(modeStr, "d", 1) == 0) {
        printf("mode=MODE_DECRYPT\n");
        mode = MODE_DECRYPT;
    } else {
        printf("[ERR] invalid mode (usage: <mode>: e = encrypt, d = decrypt)\n");
        return 1;
    }
    
    unsigned char key[8];
    char *keyStr = argv[2];
    printf("keyStr=%s\n", keyStr);
    if (strlen(keyStr) != 16) {
        printf("[ERR] invalid key lenght (8bytes == 16hex char)\n");
        return 1;
    }
    decodeHexString(keyStr, key, 8);

    unsigned char iv[8];
    char *ivStr = argv[3];
    printf("ivStr=%s\n", ivStr);
    if (strlen(ivStr) != 16) {
        printf("[ERR] invalid iv lenght (8bytes == 16hex char)\n");
        return 1;
    }
    decodeHexString(ivStr, iv, 8);

    char *inPath = argv[4];
    printf("inPath=%s\n", inPath);
    FILE *inFile = fopen(inPath, "rb");
    if (!inFile) {
        printf("[ERR] cannot open input file\n");
        return 1;
    }

    char *outPath = argv[5];
    printf("outPath=%s\n", outPath);
    FILE *outFile = fopen(outPath, "wb");
    if (!outFile) {
        printf("[ERR] cannot open output file\n");
        return 1;
    }
        
    /* --- */

    fseek(inFile, 0L, SEEK_END);
    size_t fileSize = ftell(inFile);
    printf("fileSize=%li\n", fileSize);

    if (fileSize % 8 != 0) {
        printf("[ERR] cannot use unalign file (8bytes)\n");
        return 1;
    }

    fseek(inFile, 0, SEEK_SET);
    unsigned char fBuf[4096];

    printf("start...\n");

    while (1) {
        size_t fRead = fread(fBuf, 1, sizeof(fBuf), inFile);
        if (fRead == 0) break;  //E.O.F.

        if (mode == MODE_ENCRYPT) {
            bufEncrypt(fBuf, fRead, key, iv);
        } else if (mode == MODE_DECRYPT) {
            bufDecrypt(fBuf, fRead, key, iv);
        }

        fwrite(fBuf, 1, fRead, outFile);
    }

    printf("done...!\n");
	
    return 0;
}

/* crypt functions */
int bufEncrypt(unsigned char *buf, size_t buf_len, unsigned char key[8], unsigned char iv[8]) {
    size_t n_blk = buf_len / 8;
    for (size_t b = 0; b < n_blk; b++) {
        uint8_t *blk = &buf[b * 8];
        
        /* chaining */
        for (int i = 0; i < 8; i++) {
            blk[i] ^= iv[i];
        }

        for (int r = 0; r < 6; r++) {
            for (int i = 0; i < 8; i++) {
                int prev_i = (i == 0) ? 7 : (i - 1);
                blk[i] ^= key[(i + r) % 8];
                blk[i] = ((blk[i] << 3) | (blk[i] >> 5)) & 0xFF;
                blk[i] ^= blk[prev_i];
            }
        }

        memcpy(iv, blk, 8);
    }

    return 0;
}

int bufDecrypt(unsigned char *buf, size_t buf_len, unsigned char key[8], unsigned char iv[8]) {
    size_t n_blk = buf_len / 8;
    for (size_t b = 0; b < n_blk; b++) {
        uint8_t *blk = &buf[b * 8];
        uint8_t org_blk[8];
        memcpy(org_blk, blk, 8);

        for (int r = 5; r >= 0; r--) {
            for (int i = 7; i >= 0; i--) {
                int prev_i = (i == 0) ? 7 : (i - 1);
                blk[i] ^= blk[prev_i];
                blk[i] = ((blk[i] >> 3) | (blk[i] << 5)) & 0xFF;
                blk[i] ^= key[(i + r) % 8];
            }
        }

        /* chaining */
        for (int i = 0; i < 8; i++) {
            blk[i] ^= iv[i];
        }

        memcpy(iv, org_blk, 8);
    }

    return 0;
}