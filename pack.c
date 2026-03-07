#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include <zlib.h>

#include "vupfile.h"
#include "config.h"

#include "crc.c"
#include "encrypt.c"
#include "util.c"
#include "sign.c"

typedef struct {
    char *inFile;
    char *name;
    char *version;
} IItem;

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("pack usage: pack <platformID> <packageVersion> <outPath> [-cmp] [-enc encKey] [-sig sigKeyPath] [-i inFile name version]...\n");
        return 1;
    }

    char *platformID = argv[1];
    char *packageVersion = argv[2];
    char *outPath = argv[3];
    printf("outPath = %s\n", outPath);

    IItem inputItems[100];
    int itemsCount = 0;

    int doCompress = 0;

    int doEncrypt = 0;
    uint8_t encKey[16];

    int doSign = 0;
    char* sigKeyPath;

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            if (i + 3 >= argc) {
                printf("error: -i requires 3 args\n");
                return 1;
            }

            inputItems[itemsCount].inFile = argv[i+1];
            inputItems[itemsCount].name = argv[i+2];
            inputItems[itemsCount].version = argv[i+3];

            itemsCount++;
            i += 3;
        }
        else if (strcmp(argv[i], "-cmp") == 0) { 
            doCompress = 1;
        }
        else if (strcmp(argv[i], "-enc") == 0) {
            if (i + 1 >= argc) {
                printf("error: -enc used but no enc key is provided\n");
                return 1;
            }
            if (strlen(argv[i+1]) != 32) {
                printf("error: enc key need to be 32 hex char\n");
                return 1;
            }

            doEncrypt = 1;
            parse_hex_str(argv[++i], encKey, 16);
        }
        else if (strcmp(argv[i], "-sig") == 0) {
            if (i + 1 >= argc) {
                printf("error: -sig used but no sig key path is provided\n");
                return 1;
            }

            doSign = 1;
            sigKeyPath = argv[++i];
        }
        else {
            printf("error: unknown arg: %s\n", argv[i]);
            return 1;
        }
    }

    // **********************************************************

    FILE *outFile = fopen(outPath, "wb");
    if (!outFile) {
        perror("ERROR!! - fopen fail to open out file");
        return 1;
    }

    // initial offset of first data after headers
    int offset = sizeof(VupHeader) + sizeof(ExInfoHeader) + itemsCount * sizeof(ItemEntryHeader);
    if (doSign == 1) {
        offset += SIGNATURE_SIZE;   //for exhdr signature
    }
    if (fseek(outFile, offset, SEEK_SET) != 0) {
        perror("ERROR!! - fseek fail to seek out file");
        return 1;
    }

    ItemEntryHeader items[itemsCount];

    for (int i = 0; i < itemsCount; i++) {
        ItemEntryHeader itemEntry;

        printf("item%d:\n", i);
        printf("  inFile = %s\n", inputItems[i].inFile);
        FILE *inFile = fopen(inputItems[i].inFile, "rb");
        if (!inFile) {
            perror("ERROR!! - fopen fail to open in file");
            return 1;
        }

        printf("  name = %s\n", inputItems[i].name);
        if (strlen(inputItems[i].name) > sizeof(itemEntry.name)) {
            printf("\nERROR!! - name %s is too long, max len is %li", inputItems[i].name, sizeof(itemEntry.name));
            return 1;
        }
        strncpy(itemEntry.name, inputItems[i].name, sizeof(itemEntry.name));

        printf("  version = %s\n", inputItems[i].version);
        if (strlen(inputItems[i].version) > sizeof(itemEntry.version)) {
            printf("\nERROR!! - version %s is too long, max len is %li", inputItems[i].version, sizeof(itemEntry.version));
            return 1;
        }
        strncpy(itemEntry.version, inputItems[i].version, sizeof(itemEntry.version));

        printf("  offset = %i\n", offset);
        itemEntry.offset = offset;

        printf("  itemID = %i\n", i);
        itemEntry.itemID = i;
        
        char *buf = malloc(CHUNK_SIZE + 32); //allow extra bytes for encrypt padding purpose
        if (!buf) {
            perror("ERROR!! - malloc fail to allocate data buffer");
            return 1;
        }

        size_t read;
        int chunkIdx = 0;
        int outSize = 0;
        int storedSize = 0;

        while ((read = fread(buf, 1, CHUNK_SIZE, inFile)) > 0) {
            printf("[chunk%i] read %zu byte\n", chunkIdx, read);

            ChunkHeader ch;
            ch.chunkIndex = chunkIdx;
            ch.chunkDataAttributes = 0;
            ch.chunkExtraHeaderSize = 0;
            ch.chunkOutSize = read;
            ch.chunkOutChecksum = calc_crc32(buf, read);
            //printf("[chunk%i] chk: %x\n", chunkCount, ch.chunkOutChecksum);

            size_t chunkStoredSize = read;

            if (doCompress == 1) { // ZLIB compress utilize ZLIB library
                printf("[chunk%i] compress..?\n", chunkIdx);

                uLong destLen = compressBound(chunkStoredSize);  //estimation of max compressed size 
                char *compBuf = malloc(destLen);
                if (!compBuf) {
                    perror("ERROR!! - malloc fail to allocate comp data buffer");
                    return 1;
                }

                int compResult = compress(compBuf, &destLen, buf, chunkStoredSize);
                if (compResult != Z_OK) {
                    perror("ERROR!! - compress fail to compress data");
                    return 1;
                }
                
                /* determine if it is worth to store a compressed chunk
                if the compressed data is not at least 20% smaller, discard compression. */
                if (destLen * 100 <= chunkStoredSize * 80) {
                    printf("[chunk%i] comp %zu -> %lu (%.1f%%)\n", 
                        chunkIdx, chunkStoredSize, destLen, (100.0 * destLen) / chunkStoredSize);

                    chunkStoredSize = destLen;
                    ch.chunkDataAttributes |= DATA_ATTR_COMPRESSED;

                    memcpy(buf, compBuf, destLen);
                }
                
                free(compBuf);
            }

            if (doEncrypt == 1) { // AES encrypt utilize OPENSSL library
                printf("[chunk%i] encrypt..\n", chunkIdx);

                char *encBuf = malloc(CHUNK_SIZE + 32);
                if (!encBuf) {
                    perror("ERROR!! - malloc fail to allocate enc data buffer");
                    return 1;
                }

                int encSize = encrypt(buf, chunkStoredSize, encKey, encKey, encBuf);
                chunkStoredSize = encSize;
                ch.chunkDataAttributes |= DATA_ATTR_ENCRYPTED;

                memcpy(buf, encBuf, encSize);
                free(encBuf);
            }

            unsigned char sig[SIGNATURE_SIZE];
            if (doSign == 1) { // RSA sign utilize OPENSSL library
                printf("[chunk%i] sign..\n", chunkIdx);

                if (!sign_data(buf, chunkStoredSize, sigKeyPath, sig)) {
                    perror("ERROR!! - sign fail to sign data");
                    return 1;
                }

                ch.chunkExtraHeaderSize = SIGNATURE_SIZE;
                ch.chunkDataAttributes |= DATA_ATTR_SIGNED;
            }

            ch.chunkDownloadSize = chunkStoredSize;
            
            if (!fwrite(&ch, sizeof(ChunkHeader), 1, outFile)) {
                perror("ERROR!! - fwrite fail to write chunk header");
                return 1;
            };
            if (doSign == 1) {
                if (!fwrite(sig, 1, SIGNATURE_SIZE, outFile)) {
                    perror("ERROR!! - fwrite fail to write signature");
                    return 1;
                };
            }
            if (!fwrite(buf, 1, chunkStoredSize, outFile)) {
                perror("ERROR!! - fwrite fail to write chunk data");
                return 1;
            };

            size_t write = sizeof(ChunkHeader) + ch.chunkExtraHeaderSize + chunkStoredSize;
            printf("[chunk%i] write %zu byte\n", chunkIdx, write);

            outSize += read;
            storedSize += write;
            chunkIdx++;
        }

        fclose(inFile);
        free(buf);

        printf("  chunkCount = %i\n", chunkIdx);
        itemEntry.chunkCount = chunkIdx;

        printf("  downloadSize = %i\n", storedSize);
        itemEntry.downloadSize = storedSize;

        printf("  outSize = %i\n", outSize);
        itemEntry.outSize = outSize;

        items[i] = itemEntry;
        offset += storedSize;
    }

    //reset seek to start position to write headers
    if (fseek(outFile, 0, SEEK_SET) != 0) {
        perror("ERROR!! - fseek fail to seek out file");
        return 1;
    }

    //ex info header
    ExInfoHeader i;

    printf("fileSize = %i\n", offset);
    i.fileSize = offset;

    printf("itemsCount = %i\n", itemsCount);
    i.itemsCount = itemsCount;

    printf("packageVersion = %i\n", atoi(packageVersion));
    i.packageVersion = atoi(packageVersion);

    time_t creationDate = time(NULL);
    printf("creationDate = %s", ctime(&creationDate));
    i.creationDate = (int)creationDate;

    printf("chunkSize = %i\n", CHUNK_SIZE);
    i.chunkSize = CHUNK_SIZE;

    printf("platformID = %s\n", platformID);
    if (strlen(platformID) > PLATFORM_ID_SIZE) {
        printf("\nERROR!! - platformID %s is too long, max len is %i", platformID, PLATFORM_ID_SIZE);
        return 1;
    }
    strncpy(i.platformID, platformID, PLATFORM_ID_SIZE);

    //join ex hdr
    size_t exSize = sizeof(ExInfoHeader) + itemsCount * sizeof(ItemEntryHeader);
    if (doSign == 1) {
        exSize += SIGNATURE_SIZE;
    }
    char *exBuf = malloc(exSize);
    memcpy(exBuf, &i, sizeof(ExInfoHeader));
    memcpy(exBuf + sizeof(ExInfoHeader), items, itemsCount * sizeof(ItemEntryHeader));

    unsigned char sig[SIGNATURE_SIZE];
    if (doSign == 1) {
        printf("[exhdr] sign..\n");

        if (!sign_data(exBuf, exSize - SIGNATURE_SIZE, sigKeyPath, sig)) {
            perror("ERROR!! - sign fail to sign data");
            return 1;
        }

        memcpy(exBuf + sizeof(ExInfoHeader) + itemsCount * sizeof(ItemEntryHeader), sig, SIGNATURE_SIZE);
    }

    uint32_t exChecksum = calc_crc32(exBuf, exSize);
    //printf("[exhdr] chk: %x\n", ex_checksum);

    //vup header
    VupHeader h;
    strncpy(h.magicBytes, UPG_MAGIC_BYTES, sizeof(UPG_MAGIC_BYTES) -1);
    h.exHeaderDataAttributes = 0;
    if (doSign == 1) {
        h.exHeaderDataAttributes |= DATA_ATTR_SIGNED;
    }
    h.pad = 0;
    h.exHeaderSize = exSize;
    h.exHeaderChecksum = exChecksum;

    if (!fwrite(&h, sizeof(h), 1, outFile)) {
        perror("ERROR!! - fwrite fail to write vup header");
        return 1;
    };
    if (!fwrite(exBuf, exSize, 1, outFile)) {
        perror("ERROR!! - fwrite fail to write ex header");
        return 1;
    };

    free(exBuf);
    fclose(outFile);
    return 0;
}
