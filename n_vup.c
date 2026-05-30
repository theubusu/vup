#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include "n_vup.h"
#include "n_sys.c"

#include "ext/md5.h"
#include "ext/md5.c"

/* Logging function */
void v_log(int lvl, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

int vup_check_signature(FILE *vup_file, int data_size, unsigned char* signature) {
    return 0;
}

int vup_check_and_mount(const char *vup_filename) {

    FILE *vup_file = fopen(vup_filename, "rb");
    if (!vup_file) {
        v_log(1, "%s FAIL - cannot open vup file %s\n", "vup_check_and_mount", vup_filename);
        return -1;
    }

    fseek(vup_file, 0L, SEEK_END);
    size_t file_size = ftell(vup_file);
    if (file_size < VUP_INFO_SIZE + SIGNATURE_HEADER_SIZE + SIGNATURE_SIZE) {
        v_log(1, "%s FAIL - file's size (%i) is not enough.\n", "vup_check_and_mount", file_size);
        return 1;
    }

    //signature
    fseek(vup_file, file_size - SIGNATURE_SIZE - SIGNATURE_HEADER_SIZE, SEEK_SET);
    SignatureHeader sig_hdr;
    if (fread(&sig_hdr, SIGNATURE_HEADER_SIZE, 1, vup_file) != 1) {
        v_log(1, "%s FAIL - cannot read signature heading\n", "vup_check_and_mount");
        return 1;
    }
    if (strncmp(sig_hdr.sig_marker, SIG_MARKER, 4) != 0) {
        v_log(1, "%s FAIL - there is not signature marker\n", "vup_check_and_mount");
        return 1;
    }
    v_log(0, "vup signature info:: signature_size %i, data_size: %i\n", sig_hdr.signature_size, sig_hdr.data_size);
    if (sig_hdr.signature_size != SIGNATURE_SIZE) {
        v_log(1, "%s FAIL - sigature size is not matched\n", "vup_check_and_mount");
        return 1;
    }
    unsigned char sig[SIGNATURE_SIZE];
    if (fread(&sig, SIGNATURE_SIZE, 1, vup_file) != 1) {
        v_log(1, "%s FAIL - cannot read signature\n", "vup_check_and_mount");
        return 1;
    }
    if (vup_check_signature(vup_file, sig_hdr.data_size, sig) != 0) {
        v_log(1, "%s FAIL - signature check failed\n", "vup_check_and_mount");
        return 1;
    }

    //vup info
    fseek(vup_file, file_size - SIGNATURE_SIZE - SIGNATURE_HEADER_SIZE - VUP_INFO_SIZE, SEEK_SET);
    VupInfo vup_info;
    if (fread(&vup_info, VUP_INFO_SIZE, 1, vup_file) != 1) {
        v_log(1, "%s FAIL - cannot read vup info\n", "vup_check_and_mount");
        return 1;
    }
    if (strncmp(vup_info.vup_marker, VUP_MARKER, 4) != 0) {
        v_log(1, "%s FAIL - there is not vup marker\n", "vup_check_and_mount");
        return 1;
    }

    v_log(0, "== %s's VUP info ==\n", vup_filename);
    v_log(0, "marker:       %s\n", vup_info.vup_marker);
    v_log(0, "size:         %i\n", vup_info.vup_size);
    v_log(0, "type:         %i\n", vup_info.vup_type);
    v_log(0, "force:        %i\n", vup_info.vup_force);
    v_log(0, "obscure:      %i\n", vup_info.vup_obscure);
    v_log(0, "version:      %i\n", vup_info.vup_version);
    v_log(0, "project:      %s\n", vup_info.project_name);
    v_log(0, "model:        %s\n", vup_info.model_name);
    v_log(0, "file name:    %s\n", vup_info.file_name);
    v_log(0, "date:         %s\n", vup_info.date);

    /* checking vup compatible */
    if (vup_info.vup_size > VUP_MAX_SIZE) {
        v_log(1, "%s FAIL - vup size OVER (max=%i, vup=%i)\n", "vup_check_and_mount", VUP_MAX_SIZE, vup_info.vup_size);
        return 1;
    }

    char *system_project = get_system_project_name();
    if (strncmp(vup_info.project_name, system_project, 32) != 0) {
        v_log(1, "%s FAIL - not aplicable PROJECT (system=%s, vup=%s).\n", "vup_check_and_mount", system_project, vup_info.project_name);
        return 1;
    }
    char *system_generic_model = get_system_generic_model_name();
    if (strncmp(vup_info.model_name, system_generic_model, 16) != 0) {
        v_log(1, "%s FAIL - not aplicable MODEL (system=%s, vup=%s).\n", "vup_check_and_mount", system_generic_model, vup_info.model_name);
        return 1;
    }

    int system_ver = get_system_version();
    if (vup_info.vup_force == 1) {
        v_log(0, "VUP FORCE UpDate %i -> %i\n", system_ver, vup_info.vup_version);
    } else {   
        if (vup_info.vup_version <= system_ver) {
            v_log(1, "%s FAIL - not aplicable VERSION (system=%i, vup=%i).\n", "vup_check_and_mount", system_ver, vup_info.vup_version);
            return 1;
        }
        v_log(0, "VUP UpDate %i -> %i\n", system_ver, vup_info.vup_version);
    }
    v_log(0, "VUP Check OK\n");
    
    /* writing output file */
    mkdir(VUP_OUT_PATH, 0755);

    char vup_path[128];
    snprintf(vup_path, sizeof(vup_path), "%s/%s", VUP_OUT_PATH, vup_info.file_name);
    v_log(0, "VUP download path = %s\n", vup_path);

    FILE *out_file = fopen(vup_path, "wb");
    if (!out_file) {
        v_log(1, "%s FAIL - cannot open out file %s\n", "vup_check_and_mount", vup_path);
        fclose(vup_file);
        return -1;
    }

    /* for decryption parameter */
    uint8_t key[8];
    uint8_t iv[8];
    uint8_t prev_blk[8];
    if (vup_info.vup_obscure == 1) {
        /* setup key*/
        memcpy(key, SECURE_KEY, 8);
        /* setup iv*/
        for (int i = 0; i < 8; i++) {
            iv[i] = key[i] ^ (vup_info.check_sum[i] ^ vup_info.check_sum[i+8]);
        }    
        /* setup 1st block */
        memcpy(prev_blk, iv, 8);
    }

    fseek(vup_file, 0, SEEK_SET);
    size_t f_remain = vup_info.vup_size;
    unsigned char f_buf[4096];

    /* md5 veryfication setup */
    MD5Context md5_ctx;
    md5Init(&md5_ctx);

    v_log(0, "Start copy VUP file\n");

    while (f_remain > 0) {
        size_t f_to_read = f_remain < sizeof(f_buf) ? f_remain : sizeof(f_buf);

        size_t f_read = fread(f_buf, 1, f_to_read, vup_file);
        if (f_read == 0) break;

        /* decrypt buffer if enabled*/
        if (vup_info.vup_obscure == 1) {

            size_t n_blk = f_read / 8;
            for (size_t b = 0; b < n_blk; b++) {
                uint8_t *blk = &f_buf[b * 8];
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
                    blk[i] ^= prev_blk[i];
                }

                memcpy(prev_blk, org_blk, 8);
            }
        }

        md5Update(&md5_ctx, f_buf, f_read);
        fwrite(f_buf, 1, f_read, out_file);
        f_remain -= f_read;
    }

    md5Finalize(&md5_ctx);
    v_log(0, "Finish copy VUP file\n");
    if (memcmp(md5_ctx.digest, vup_info.check_sum, 16) != 0) {
        v_log(1, "%s FAIL - check sum not matched, abort update!!\n", "vup_check_and_mount");
        fclose(out_file);
        unlink(vup_path);
        return 1;
    } else {
        v_log(0, "Check sum veryfication success\n");
    }
    fclose(vup_file);
    fclose(out_file);

    /* process mount vup file */
    mkdir(VUP_MOUNT_PATH, 0755);

    char cmd[1024];
    switch (vup_info.vup_type) {
        case 0:
            v_log(0, "Not mount vup...\n");
            break;
        case 1:
            v_log(0, "Extract tar vup...\n");
            snprintf(cmd, sizeof(cmd), "tar -xf %s -C %s", vup_path, VUP_MOUNT_PATH);
            break;
        case 2:
            v_log(0, "Extract targz vup...\n");
            snprintf(cmd, sizeof(cmd), "tar -xzf %s -C %s", vup_path, VUP_MOUNT_PATH);
            break;
        case 3:
            v_log(0, "Mount squashfs vup...\n");
            snprintf(cmd, sizeof(cmd), "mount -t squashfs -o loop %s %s", vup_path, VUP_MOUNT_PATH);
            break;
        case 4:
            v_log(0, "Mount ext vup...\n");
            snprintf(cmd, sizeof(cmd), "mount -t ext3 -o ro,loop %s %s", vup_path, VUP_MOUNT_PATH);
            break;
        case 255:
            v_log(0, "Exec vup...\n");
            snprintf(cmd, sizeof(cmd), "chmod +x %s && %s", vup_path, vup_path);
            break;
        default:
            v_log(1, "%s FAIL - unknown Vup type, abort update!!\n", "vup_check_and_mount");
            unlink(vup_path);
            return 1;
    }

    if (system(cmd) != 0) {
        v_log(1, "%s FAIL - vup mount failed\n", "vup_check_and_mount");
        unlink(vup_path);
        return 1;
    }

    v_log(0, "Mount vup success\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("vup filename is not provided\n");
        return 1;
    }
    
    if (vup_check_and_mount(argv[1]) == 0) {
        printf("[VUP] check and mount success\n");
    } else {
        printf("[VUP] check and mount FAIL\n");
    }

    return 0;
}