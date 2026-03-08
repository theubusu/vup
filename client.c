#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <zlib.h>

#include "vupfile.h"
#include "client_config.h"

#include "crc.c"

#ifdef SUPPORT_SIGNATURE
#include "sign.c"
#endif

#ifdef SUPPORT_DECRYPT
#include "encrypt.c"
#endif

const char *getTgtDest(const char *name)
{
    for (size_t i = 0; i < TGT_TABLE_SIZE; i++) {
        if (strcmp(TGT_TABLE[i].name, name) == 0) {
            return TGT_TABLE[i].dest;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("[VUP] FAIL - VUP fileName is not provided\n");
        return 1;
    }

    char *fileName = argv[1];
    printf("[VUP] VUP fileName: %s\n", fileName);

    FILE *inFile = fopen(fileName, "rb");
    if (!inFile) {
        perror("[VUP] FAIL - Cannot open VUP File\n");
        return 1;
    }

    VupHeader h;
    if (fread(&h, sizeof(h), 1, inFile) != 1) {
        perror("[VUP] FAIL - Cannot read vup header\n");
        return 1;
    }

    if (strncmp(h.magicBytes, UPG_MAGIC_BYTES, sizeof(h.magicBytes)) != 0) {
        printf("[VUP] FAIL - Header magic bytes NG\n");
        return 1;
    }

    printf("[VUP] exhdr size:%i\n", h.exHeaderSize);
    char *exBuf = malloc(h.exHeaderSize);

    if (fread(exBuf, 1, h.exHeaderSize, inFile) != h.exHeaderSize) {
        perror("[VUP] FAIL - Cannot read ex header\n");
        return 1;
    }

    uint32_t exChk = calc_crc32(exBuf, h.exHeaderSize);
    if (exChk != h.exHeaderChecksum) {
        printf("[VUP] FAIL - Ex header checksum NG, exp:%x act:%x\n", h.exHeaderChecksum, exChk);
        return 1;
    }

    #ifdef SUPPORT_SIGNATURE
    if ((h.exHeaderDataAttributes & DATA_ATTR_SIGNED) != 0) {
        unsigned char sig[SIGNATURE_SIZE];
        memcpy(sig, exBuf + (h.exHeaderSize - SIGNATURE_SIZE), SIGNATURE_SIZE);

        int res = verifyDataRSA1024(exBuf, h.exHeaderSize - SIGNATURE_SIZE, sig, SIGNATURE_SIZE, SIGN_PUB_KEY_FILE);
        if (res == 1) {
            printf("[VUP] ex hdr signature OK!\n");
        }
        else if (res == 0) {
            printf("[VUP] FAIL - ex hdr signature NG!\n");
            return 1;
        }
        else {
            printf("[VUP] FAIL - Cannot verify exhdr signature\n");
            return 1;
        }
    
    }
    #ifdef ENFORCE_SIGNATURE
    else {
        printf("[VUP] FAIL - Unsigned data is not allow\n");
        return 1;
    }
    #endif
    #endif

    ExInfoHeader *ex = (ExInfoHeader *)exBuf;

    printf("[VUP] vup platformID:   %s\n", ex->platformID);
    char *sysPlatformID = getenv("PLATFORM_ID");
    if (sysPlatformID == NULL) {
        printf("[VUP] sys platformID is not set, cannot compare..\n");
    } else {
        printf("[VUP] sys platformID:   %s\n", sysPlatformID);
        if (strcmp(sysPlatformID, ex->platformID) != 0) {
            printf("[VUP] Platform ID mismatch!\n");
            return 1;
        }
    }

    printf("[VUP] vup pkg ver:      %i\n", ex->packageVersion);
    char *sysPkgVer = getenv("PKG_VERSION");
    if (sysPkgVer == NULL) {
        printf("[VUP] sys pkg ver is not set, cannot compare..\n");
    } else {
        printf("[VUP] sys pkg ver:      %i\n", atoi(sysPkgVer));
        if (atoi(sysPkgVer) >= ex->packageVersion) {
            printf("[VUP] Not need update!\n");
            return 0;
        }
    }

    printf("[VUP] vup fileSize:     %i\n", ex->fileSize);
    fseek(inFile, 0L, SEEK_END);
    size_t cfileSize = ftell(inFile);
    printf("[VUP] sys fileSize:     %i\n", cfileSize);
    if (cfileSize != ex->fileSize) {
        printf("[VUP] FAIL - File size mismatch!\n");
        return 1;
    }

    time_t t = (time_t)ex->creationDate;
    printf("[VUP] vup date:         %s", ctime(&t));

    ItemEntryHeader *items = (ItemEntryHeader *)(exBuf + sizeof(ExInfoHeader));
    for (int i = 0; i < ex->itemsCount; i++) {
        printf("[VUP] item%d:\n", i);
        printf("    name:         %s\n",  items[i].name);
        printf("    version:      %s\n",  items[i].version);
        printf("    offset:       %d\n",  items[i].offset);
        printf("    itemID:       %i\n",  items[i].itemID);
        printf("    chunkCount:   %i\n",  items[i].chunkCount);
        printf("    downloadSize: %i\n",  items[i].downloadSize);
        printf("    outSize:      %i\n",  items[i].outSize);

        const char *dest = getTgtDest(items[i].name);
        if (dest) {
            printf("[VUP] target Dest:%s\n",  dest);
        } else {
            printf("[VUP] not found target dest, skip %s update\n", items[i].name);
            continue;
        }

        FILE *destFile = fopen(dest, "wb");
        if (!destFile) {
            perror("[VUP] FAIL - Cannot open dest file\n");
            return 1;
        }
        fseek(destFile, 0, SEEK_SET);

        fseek(inFile, items[i].offset, SEEK_SET);
        
        for (int chi = 0; chi < items[i].chunkCount; chi++) {

            ChunkHeader ch;
            if (fread(&ch, sizeof(ch), 1, inFile) != 1) {
                printf("[VUP] FAIL - Cannot read chunk header\n");
                return 1;
            }
            printf("[VUP] %s %i/%i, idx:%i, dwld:%i, out:%i, offs:%li\n",
                    items[i].name, chi + 1, items[i].chunkCount, ch.chunkIndex, ch.chunkDownloadSize, ch.chunkOutSize, ftell(inFile) - sizeof(ch));

            if (chi != ch.chunkIndex) {
                printf("[VUP] FAIL - chunk index mismatched\n");
                return 1;
            }

            if (ch.chunkOutSize > ex->chunkSize) {
                printf("[VUP] FAIL - invalid chunk out size\n");
                return 1;
            }

            #ifdef SUPPORT_SIGNATURE
            unsigned char sig[SIGNATURE_SIZE];
            if ((ch.chunkDataAttributes & DATA_ATTR_SIGNED) != 0) {
                fread(sig, 1, SIGNATURE_SIZE, inFile);
            }
            #ifdef ENFORCE_SIGNATURE
            else {
                printf("[VUP] FAIL - Unsigned data is not allow\n");
                return 1;
            }
            #endif
            #endif

            char *dwldBuf = malloc(ch.chunkDownloadSize);
            if (!dwldBuf) {
                perror("[VUP] FAIL - Cannot allocate data buf\n");
                return 1;
            }

            if (fread(dwldBuf, 1, ch.chunkDownloadSize, inFile) != ch.chunkDownloadSize) {
                perror("[VUP] FAIL - Cannot read chunk\n");
                return 1;
            };

            #ifdef SUPPORT_SIGNATURE
            if ((ch.chunkDataAttributes & DATA_ATTR_SIGNED) != 0) {
                int res = verifyDataRSA1024(dwldBuf, ch.chunkDownloadSize, sig, SIGNATURE_SIZE, SIGN_PUB_KEY_FILE);
                if (res == 1) {
                    printf("    sign OK\n");
                }
                else if (res == 0) {
                    printf("[VUP] FAIL - chunk signature NG!\n");
                    return 1;
                }
                else {
                    printf("[VUP] FAIL - Cannot verify chunk signature\n");
                    return 1;
                }
            }
            #endif

            char *outBuf = malloc(ch.chunkOutSize);
            memcpy(outBuf, dwldBuf, ch.chunkDownloadSize);
            int currSize = ch.chunkDownloadSize;

            #ifdef SUPPORT_DECRYPT
            if ((ch.chunkDataAttributes & DATA_ATTR_ENCRYPTED) != 0) {
                printf("    decrypt...\n");
                currSize = decrypt(dwldBuf, ch.chunkDownloadSize, ENCRYPTION_KEY, ENCRYPTION_KEY, outBuf);
                printf("    decrypt curr:%i\n", currSize);
            }
            #endif

            if ((ch.chunkDataAttributes & DATA_ATTR_COMPRESSED) != 0) {
                printf("    decompress...\n");
                char *tmpBuf = malloc(currSize);
                memcpy(tmpBuf, outBuf, currSize);

                uLongf outLen = ch.chunkOutSize;
                int uncompResult = uncompress(outBuf, &outLen, tmpBuf, currSize);
                if (uncompResult != Z_OK) {
                    printf("[VUP] FAIL - Cannot uncompress data\n");
                    return 1;
                }
            }

            uint32_t chk = calc_crc32(outBuf, ch.chunkOutSize);
            if (chk != ch.chunkOutChecksum) {
                printf("[VUP] FAIL - chunk checksum NG, exp:%x act:%x\n", ch.chunkOutChecksum, chk);
                return 1;
            } else {
                printf("    chk OK\n");
            }

            if (!fwrite(outBuf, ch.chunkOutSize, 1, destFile)) {
                perror("[VUP] FAIL - failed to write to dest file");
                return 1;
            } else {
                printf("    write OK\n");
            }

            free(outBuf);
            free(dwldBuf);
        }

        printf("[VUP] %s update is finished\n", items[i].name);
        fclose(destFile);
    }

    printf("[VUP] Version up is finished succesfully\n");
    fclose(inFile);
    return 0;
}