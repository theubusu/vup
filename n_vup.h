#include <stdint.h>

/* vup platform configuration */
#define VUP_MAX_SIZE 0xC000000
#define VUP_OUT_PATH "/tmp/vup"
#define VUP_MOUNT_PATH "/tmp/mntvup"
unsigned char SECURE_KEY[] = {0xBD, 0x17, 0xFC, 0x2D, 0x0C, 0x0C, 0x92, 0xD5};

/* vup structure */
#define VUP_INFO_SIZE 128
#define VUP_MARKER "VUP"

typedef struct __attribute__((packed)) {
    char vup_marker[4];
    uint32_t vup_size;
    uint8_t vup_type;
    uint8_t vup_force;
    uint8_t vup_obscure;
    uint8_t vup_compress;
    uint32_t vup_version;
    char project_name[32];
    char model_name[16];
    char file_name[32];
    char date[16];
    char check_sum[16];
} VupInfo;


#define SIGNATURE_HEADER_SIZE 16
#define SIGNATURE_SIZE 128
#define SIG_MARKER "SIG"

typedef struct __attribute__((packed)) {
    char sig_marker[4];
    uint32_t signature_size;
    uint32_t data_size;
    uint32_t _pad;
} SignatureHeader;