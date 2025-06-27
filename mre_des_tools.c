#include "mre_des_tools.h"

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
            if (trigeris == VM_TRUE) {vm_exit_app();}
            break;

        case VM_MSG_INACTIVE:
            break;

        case VM_MSG_QUIT:
            break;
    }
}

VMINT job1(VMWCHAR *filepath, VMINT wlen) { //encrypt

    VMFILE f_read, f_write;
    VMUINT nread;
    VMWCHAR outfile[100];
    VMWCHAR ext[8];

    vm_ascii_to_ucs2(ext, sizeof(ext), "des");
    vm_wstrncpy(outfile, filepath, vm_wstrlen(filepath) - 3);
    vm_wstrcat(outfile, ext);

    f_read = vm_file_open(filepath, MODE_READ, TRUE);
    if (f_read < 0) return -1;

    f_write = vm_file_open(outfile, MODE_CREATE_ALWAYS_WRITE, TRUE);
    if (f_write < 0) {
        vm_file_close(f_read);
        return -1;
    }

    VMDESHANDLE handle = vm_des_set_key(des_key);
    if (handle < 0) {
        vm_file_close(f_read);
        vm_file_close(f_write);
        return -1;
    }

    uint8_t buffer[CHUNK_SIZE];
    while (!vm_file_is_eof(f_read)) {
        vm_file_read(f_read, buffer, CHUNK_SIZE, &nread);
        if (nread <= 0) break;

        VMINT out_len = 0;
        uint8_t *encrypted = vm_des_encrypt(handle, buffer, nread, &out_len);
        if (!encrypted || out_len <= 0) break;

        vm_file_write(f_write, encrypted, out_len, &nread);
    }

    vm_des_reset_key(handle);
    vm_file_close(f_read);
    vm_file_close(f_write);

    return 0;
}

VMINT job(VMWCHAR *filepath, VMINT wlen) { //decrypt

    VMFILE f_read, f_write;
    VMUINT nread;
    VMWCHAR outfile[100];
    VMWCHAR ext[8];

    vm_ascii_to_ucs2(ext, sizeof(ext), "bin");
    vm_wstrncpy(outfile, filepath, vm_wstrlen(filepath) - 3);
    vm_wstrcat(outfile, ext);

    f_read = vm_file_open(filepath, MODE_READ, TRUE);
    if (f_read < 0) return -1;

    f_write = vm_file_open(outfile, MODE_CREATE_ALWAYS_WRITE, TRUE);
    if (f_write < 0) {
        vm_file_close(f_read);
        return -1;
    }

    VMDESHANDLE handle = vm_des_set_key(des_key);
    if (handle < 0) {
        vm_file_close(f_read);
        vm_file_close(f_write);
        return -1;
    }

    uint8_t buffer[CHUNK_SIZE];
    while (!vm_file_is_eof(f_read)) {
        vm_file_read(f_read, buffer, CHUNK_SIZE, &nread);
        if (nread <= 0) break;

        VMINT out_len = 0;
        uint8_t *decrypted = vm_des_decrypt(handle, buffer, nread, &out_len);
        if (!decrypted || out_len <= 0) break;

        vm_file_write(f_write, decrypted, out_len, &nread);
    }

    vm_des_reset_key(handle);
    vm_file_close(f_read);
    vm_file_close(f_write);

    return 0;
}

void save_text(VMINT state, VMWSTR text) {

    VMINT lenght;

    lenght = wstrlen(text);

    if (state == VM_INPUT_OK && lenght > 0 ) {
       vm_chset_convert(VM_CHSET_UCS2, VM_CHSET_UTF8, (VMSTR)text, des_key, vm_wstrlen(text) + 1);
       des_key[8] = '\0';
       check_selector = vm_selector_run(0, 0, job);
       if (check_selector == 0) {trigeris = VM_TRUE;}

    } else {
       vm_exit_app();
    }

}