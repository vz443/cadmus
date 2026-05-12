#include "../include/kms.h"
#include "../include/crypto.h"
#include <stdio.h>
#include <string.h>

void kms_derive_key(const char *password, cadmus_u8 key_out[CADMUS_KEY_LEN]) {
    if (password == NULL || key_out == NULL) {
        return;
    }

    crypto_mix_bytes((const cadmus_u8 *)password, (cadmus_u32)strlen(password), key_out);
}

CadmusError kms_store_session(const char *username, const cadmus_u8 key[CADMUS_KEY_LEN]) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    char stored_username[CADMUS_USERNAME_MAX];

    if (username == NULL || key == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    if (kms_session_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_OVERFLOW;
    }

    memset(stored_username, 0, sizeof(stored_username));
    strncpy(stored_username, username, CADMUS_USERNAME_MAX - 1);

    fptr = fopen(path, "wb");
    if (fptr == NULL) {
        return CADMUS_ERR_FILE_IO;
    }

    if (fwrite(stored_username, 1, sizeof(stored_username), fptr) != sizeof(stored_username) ||
        fwrite(key, 1, CADMUS_KEY_LEN, fptr) != CADMUS_KEY_LEN) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }
    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }
    return CADMUS_OK;
}

CadmusError kms_load_session(char username_out[CADMUS_USERNAME_MAX], cadmus_u8 key_out[CADMUS_KEY_LEN]) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    char stored_username[CADMUS_USERNAME_MAX];
    cadmus_u8 stored_key[CADMUS_KEY_LEN];

    if (kms_session_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_OVERFLOW;
    }

    fptr = fopen(path, "rb");
    if (fptr == NULL) {
        return CADMUS_ERR_NOT_AUTHENTICATED;
    }

    if (fread(stored_username, 1, sizeof(stored_username), fptr) != sizeof(stored_username) ||
        fread(stored_key, 1, sizeof(stored_key), fptr) != sizeof(stored_key)) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }
    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }

    stored_username[CADMUS_USERNAME_MAX - 1] = '\0';
    if (username_out != NULL) {
        memcpy(username_out, stored_username, sizeof(stored_username));
    }
    if (key_out != NULL) {
        memcpy(key_out, stored_key, sizeof(stored_key));
    }
    crypto_secure_zero(stored_key, sizeof(stored_key));
    return CADMUS_OK;
}

CadmusError kms_clear_session(void) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    cadmus_u8 zeros[CADMUS_USERNAME_MAX + CADMUS_KEY_LEN];

    if (kms_session_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_OVERFLOW;
    }

    fptr = fopen(path, "r+b");
    if (fptr == NULL) {
        return CADMUS_ERR_NOT_AUTHENTICATED;
    }

    memset(zeros, 0, sizeof(zeros));
    if (fwrite(zeros, 1, sizeof(zeros), fptr) != sizeof(zeros)) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }
    crypto_secure_zero(zeros, sizeof(zeros));

    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }
    if (remove(path) != 0) {
        return CADMUS_ERR_FILE_IO;
    }
    return CADMUS_OK;
}

CadmusError kms_cadmus_dir(char *buf, int buf_size) {
    if (buf == NULL || buf_size <= 1) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    strcpy(buf, ".");
    return CADMUS_OK;
}

CadmusError kms_session_path(char *buf, int buf_size) {
    if (buf == NULL || buf_size <= (int)strlen(CADMUS_SESSION_FILE)) {
        return CADMUS_ERR_OVERFLOW;
    }
    strcpy(buf, CADMUS_SESSION_FILE);
    return CADMUS_OK;
}

CadmusError kms_store_path(char *buf, int buf_size) {
    if (buf == NULL || buf_size <= (int)strlen(CADMUS_DOC_PREFIX)) {
        return CADMUS_ERR_OVERFLOW;
    }
    strcpy(buf, CADMUS_DOC_PREFIX);
    return CADMUS_OK;
}

CadmusError kms_users_path(char *buf, int buf_size) {
    if (buf == NULL || buf_size <= (int)strlen(CADMUS_USERS_FILE)) {
        return CADMUS_ERR_OVERFLOW;
    }
    strcpy(buf, CADMUS_USERS_FILE);
    return CADMUS_OK;
}

CadmusError kms_index_path(char *buf, int buf_size) {
    if (buf == NULL || buf_size <= (int)strlen(CADMUS_INDEX_FILE)) {
        return CADMUS_ERR_OVERFLOW;
    }
    strcpy(buf, CADMUS_INDEX_FILE);
    return CADMUS_OK;
}

CadmusError kms_init_dirs(void) {
    return CADMUS_OK;
}
