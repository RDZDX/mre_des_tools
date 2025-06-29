#include "mre_des_tools.h"

#define DES_BLOCK_SIZE 8

VMBOOL trigeris = VM_FALSE;
VMWCHAR title_name[22] = {0};
VMINT check_selector = -1;
VMUINT8 des_key[8] = {0};

void vm_main(void) {

    vm_reg_sysevt_callback(handle_sysevt);
    vm_ascii_to_ucs2(title_name, (strlen("Input password:") + 1) * 2, "Input password:");
    vm_input_set_editor_title(title_name);
    vm_input_text3(NULL, 1200, 32, save_text);
}

void handle_sysevt(VMINT message, VMINT param) {

    switch (message) {
        case VM_MSG_CREATE:
        case VM_MSG_ACTIVE:
            break;
        case VM_MSG_PAINT:
            if (trigeris == VM_TRUE) { vm_exit_app(); }
            break;
        case VM_MSG_INACTIVE:
        case VM_MSG_QUIT:
            break;
    }
}

void save_text(VMINT state, VMWSTR text) {

    VMCHAR tmp[100] = {0};
    VMINT lenght = vm_wstrlen(text);
    int i;

    if (state == VM_INPUT_OK && lenght > 0) {
        vm_chset_convert(VM_CHSET_UCS2, VM_CHSET_UTF8, (VMSTR)text, tmp, (lenght + 1) * 2);
        memset(des_key, 0, sizeof(des_key));
        int copied = copy_utf8_safely(tmp, des_key, 8);

        for (i = copied; i < 8; i++) {
            des_key[i] = 0x00;
        }

        check_selector = vm_selector_run(0, 0, job);
        if (check_selector == 0) { trigeris = VM_TRUE; }
    } else {
        vm_exit_app();
    }
}


int utf8_char_length(unsigned char c) {

    if ((c & 0x80) == 0x00) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return -1;
}

int copy_utf8_safely(const char* input, unsigned char* output, int max_bytes) {

    int in_pos = 0, out_pos = 0;
    int i;
    while (input[in_pos] != '\0' && out_pos < max_bytes) {
        int len = utf8_char_length((unsigned char)input[in_pos]);
        if (len < 0 || (out_pos + len > max_bytes)) break;
        for (i = 0; i < len; i++) {
            output[out_pos++] = input[in_pos++];
        }
    }
    return out_pos;
}

VMINT job(VMWCHAR *filepath, VMINT wlen) {

    VMFILE f_read, f_write;
    VMUINT file_size, nread;
    VMWCHAR outfile[100], ext[8];
    VMDESHANDLE handle;
    uint8_t *input_buf = NULL;
    uint8_t *encrypted_buf = NULL;
    VMINT padded_size, out_len;
    int i;

    vm_ascii_to_ucs2(ext, sizeof(ext), "des");
    vm_wstrncpy(outfile, filepath, vm_wstrlen(filepath) - 3);
    vm_wstrcat(outfile, ext);

    f_read = vm_file_open(filepath, MODE_READ, TRUE);
    if (f_read < 0) return -1;

    if (vm_file_getfilesize(f_read, &file_size) < 0) {
        vm_file_close(f_read);
        return -1;
    }

    padded_size = ((file_size + DES_BLOCK_SIZE - 1) / DES_BLOCK_SIZE) * DES_BLOCK_SIZE;
    input_buf = vm_malloc(padded_size);
    if (!input_buf) {
        vm_file_close(f_read);
        return -1;
    }

    memset(input_buf, 0, padded_size);
    if (vm_file_read(f_read, input_buf, file_size, &nread) != file_size) {
        vm_free(input_buf);
        vm_file_close(f_read);
        return -1;
    }
    vm_file_close(f_read);

    uint8_t pad_val = padded_size - file_size;
    for (i = file_size; i < padded_size; i++) {
        input_buf[i] = pad_val;
    }

    handle = vm_des_set_key(des_key);
    if (handle < 0) {
        vm_free(input_buf);
        return -1;
    }

    encrypted_buf = vm_des_encrypt(handle, input_buf, padded_size, &out_len);
    vm_des_reset_key(handle);
    vm_free(input_buf);

    if (!encrypted_buf || out_len <= 0) {
        return -1;
    }

    f_write = vm_file_open(outfile, MODE_CREATE_ALWAYS_WRITE, TRUE);
    if (f_write < 0) return -1;

    vm_file_write(f_write, (VMUINT8*)&file_size, sizeof(VMUINT), &nread);      // orig size
    vm_file_write(f_write, encrypted_buf, out_len, &nread);                    // ecoded data
    vm_file_close(f_write);

    return 0;
}

VMINT job1(VMWCHAR *filepath, VMINT wlen) {

    VMFILE f_read, f_write;
    VMUINT nread;
    VMWCHAR outfile[100], ext[8];
    VMUINT file_size;
    VMINT total_size;
    uint8_t *encrypted_buf = NULL;
    uint8_t *decrypted_buf = NULL;
    VMINT out_len;
    VMDESHANDLE handle;

    vm_ascii_to_ucs2(ext, sizeof(ext), "bin");
    vm_wstrncpy(outfile, filepath, vm_wstrlen(filepath) - 3);
    vm_wstrcat(outfile, ext);

    f_read = vm_file_open(filepath, MODE_READ, TRUE);
    if (f_read < 0) return -1;

    if (vm_file_read(f_read, (VMUINT8*)&file_size, sizeof(VMUINT), &nread) != sizeof(VMUINT)) { //first 4 byte
        vm_file_close(f_read);
        return -1;
    }

    if (vm_file_getfilesize(f_read, (VMUINT*)&total_size) < 0) {
        vm_file_close(f_read);
        return -1;
    }
    total_size -= sizeof(VMUINT);  // remove first 4 byte

    encrypted_buf = vm_malloc(total_size);
    if (!encrypted_buf) {
        vm_file_close(f_read);
        return -1;
    }

    if (vm_file_read(f_read, encrypted_buf, total_size, &nread) != total_size) {
        vm_free(encrypted_buf);
        vm_file_close(f_read);
        return -1;
    }
    vm_file_close(f_read);

    handle = vm_des_set_key(des_key);
    if (handle < 0) {
        vm_free(encrypted_buf);
        return -1;
    }

    decrypted_buf = vm_des_decrypt(handle, encrypted_buf, total_size, &out_len);
    vm_des_reset_key(handle);
    vm_free(encrypted_buf);

    if (!decrypted_buf || out_len <= 0) {
        return -1;
    }

    f_write = vm_file_open(outfile, MODE_CREATE_ALWAYS_WRITE, TRUE);
    if (f_write < 0) {
        return -1;
    }

    vm_file_write(f_write, decrypted_buf, file_size, &nread); //write data without pading
    vm_file_close(f_write);

    return 0;
}