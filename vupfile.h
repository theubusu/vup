#define UPG_MAGIC_BYTES "MTFDTVUP"

typedef struct __attribute__((packed)) {
    char magicBytes[8];
    uint8_t exHeaderDataAttributes; //use for sign exheader
    uint8_t pad;
    uint16_t exHeaderSize;     //size of following exHeader and package entries.
    uint32_t exHeaderChecksum; //The crc32 hash sum of exHeaderSize following bytes.

} VupHeader;

#define PLATFORM_ID_SIZE 0x20

typedef struct __attribute__((packed)) {
    uint32_t fileSize;
    uint16_t itemsCount;
    uint16_t packageVersion;
    uint32_t creationDate;
    uint32_t chunkSize;
    
    char platformID[PLATFORM_ID_SIZE];

} ExInfoHeader;

typedef struct __attribute__((packed)) {
    char name[8];
    char version[8];
    
    uint32_t offset;
    uint16_t itemID;
    uint16_t chunkCount;
    uint32_t downloadSize;          //The size that is stored in file, download size.
    uint32_t outSize;               //The size of out data after process.

} ItemEntryHeader;

#define SIGNATURE_SIZE 128

#define DATA_ATTR_COMPRESSED   (1 << 2)
#define DATA_ATTR_SCRAMBLED    (1 << 3)
#define DATA_ATTR_ENCRYPTED    (1 << 4)
#define DATA_ATTR_SIGNED	   (1 << 5)

typedef struct __attribute__((packed)) {
    uint16_t chunkIndex;
    uint8_t  chunkDataAttributes;
    uint8_t  chunkExtraHeaderSize;
    uint32_t chunkDownloadSize;
    uint32_t chunkOutSize;
    uint32_t chunkOutChecksum;      //The crc32 of chunk out data

} ChunkHeader;