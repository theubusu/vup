// configuration of sample VUP client

//#define VUPFILE_PATH "MTF_DTV_UPG.ROM"

//is support openssl decrypt
#define SUPPORT_DECRYPT

//encryption key (16 bytes aes key)
unsigned char ENCRYPTION_KEY[] = {0x56, 0x65, 0x72, 0x79, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x45, 0x6e, 0x63, 0x4b, 0x65, 0x79};

//is support openssl signature check
#define SUPPORT_SIGNATURE

//enforce signed data only
//#define ENFORCE_SIGNATURE

//signature key path
#define SIGN_PUB_KEY_FILE "public.pem"

// -- target for flash --
typedef struct {
    const char *name;
    const char *dest;
} flashTarget;

flashTarget TGT_TABLE[] = {
    //{"relnote", "nv/sys/relnote.txt"},
    {"boot",    "_bank/boot"},
    {"linux",   "_bank/kern"},
    {"rootfs",  "_bank/rootfs"},
    {"config",  "_bank/config"},
    {"app",     "_bank/app"},
    {"extra",   "_bank/extra"},
};

size_t TGT_TABLE_SIZE = sizeof(TGT_TABLE) / sizeof(TGT_TABLE[0]);