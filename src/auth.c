#include "../include/auth.h"
#include "../include/crypto.h"
#include "../include/kms.h"
#include <stdio.h>
#include <string.h>

#define CADMUS_HASH_HEX_LEN ((int)(sizeof(unsigned long) * 2 + 1))

static CadmusError auth_lookup_hashed_pw(const char *username, char hash_out[CADMUS_HASH_HEX_LEN]);
static unsigned long auth_hash_text(const char *text);
static int auth_has_session_for_user(const char *username);
static int auth_create_session(const char *username, const char *password);
static int auth_invalid_field(const char *value);
static int auth_invalid_username(const char *value);
static void auth_hash_password(const char *password, char out[CADMUS_HASH_HEX_LEN]);

CadmusError auth_login(const char *username, const char *password) {
    char password_hash[CADMUS_HASH_HEX_LEN];
    char incomingHash[CADMUS_HASH_HEX_LEN];

    if (auth_invalid_username(username) || auth_invalid_field(password)) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    if (auth_lookup_hashed_pw(username, password_hash) != CADMUS_OK) {
        return CADMUS_ERR_USER_NOT_FOUND;
    }

    auth_hash_password(password, incomingHash);
    if (strcmp(incomingHash, password_hash) != 0) {
        return CADMUS_ERR_INVALID_CREDENTIALS;
    }

    if (auth_has_session_for_user(username)) {
        return CADMUS_OK;
    }

    if (!auth_create_session(username, password)) {
        return CADMUS_ERR_FILE_IO;
    }

    return CADMUS_OK;
}

CadmusError auth_logout(void) {
    return kms_clear_session();
}

CadmusError auth_register(const char *username, const char *password) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    char passwordHash[CADMUS_HASH_HEX_LEN];
    CadmusError err;

    if (auth_invalid_username(username) || auth_invalid_field(password)) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    err = kms_init_dirs();
    if (err != CADMUS_OK) {
        return err;
    }

    if (auth_user_exists(username)) {
        return CADMUS_ERR_USER_EXISTS;
    }

    err = kms_users_path(path, sizeof(path));
    if (err != CADMUS_OK) {
        return err;
    }

    fptr = fopen(path, "a");
    if (fptr == NULL) {
        return CADMUS_ERR_FILE_IO;
    }

    auth_hash_password(password, passwordHash);
    if (fprintf(fptr, "%s:%s\n", username, passwordHash) < 0) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }

    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }

    return CADMUS_OK;
}

CadmusError auth_whoami(char out[CADMUS_USERNAME_MAX]) {
    if (out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    return kms_load_session(out, NULL);
}

int auth_user_exists(const char *username) {
    char password_hash[CADMUS_HASH_HEX_LEN];

    if (auth_invalid_username(username)) {
        return 0;
    }

    return auth_lookup_hashed_pw(username, password_hash) == CADMUS_OK;
}

static int auth_invalid_field(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 1;
    }

    return strchr(value, ':') != NULL || strchr(value, '\n') != NULL || strchr(value, '\r') != NULL;
}

static int auth_invalid_username(const char *value) {
    if (auth_invalid_field(value)) {
        return 1;
    }

    return strlen(value) >= CADMUS_USERNAME_MAX;
}

static void auth_hash_password(const char *password, char out[CADMUS_HASH_HEX_LEN]) {
    unsigned long hash;

    hash = auth_hash_text(password);
    snprintf(out, CADMUS_HASH_HEX_LEN, "%0*lx", (int)(sizeof(hash) * 2), hash);
}

static int auth_has_session_for_user(const char *username) {
    char current_user[CADMUS_USERNAME_MAX];

    if (username == NULL) {
        return 0;
    }
    if (auth_whoami(current_user) != CADMUS_OK) {
        return 0;
    }
    return strcmp(current_user, username) == 0;
}

static int auth_create_session(const char *username, const char *password) {
    char passwordHash[CADMUS_HASH_HEX_LEN];
    cadmus_u8 key[CADMUS_KEY_LEN];

    if (username == NULL || password == NULL) {
        return 0;
    }

    auth_hash_password(password, passwordHash);
    kms_derive_key(passwordHash, key);
    if (kms_store_session(username, key) != CADMUS_OK) {
        crypto_secure_zero(key, sizeof(key));
        return 0;
    }
    crypto_secure_zero(key, sizeof(key));
    return 1;
}

static unsigned long auth_hash_text(const char *text) {
    unsigned long hash = 5381;
    int c;

    while ((c = *text++) != 0) {
        hash = (hash * 33u) ^ (unsigned long)c;
    }

    return hash;
}

static CadmusError auth_lookup_hashed_pw(const char *username, char hash_out[CADMUS_HASH_HEX_LEN]) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    char line[256];

    if (username == NULL || hash_out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    if (kms_users_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_FILE_IO;
    }

    fptr = fopen(path, "r");
    if (fptr == NULL) {
        return CADMUS_ERR_FILE_IO;
    }

    while (fgets(line, sizeof(line), fptr)) {
        char *separator;
        char *hash;
        size_t hashLen;

        separator = strchr(line, ':');
        if (separator == NULL) {
            continue;
        }

        *separator = '\0';
        if (strcmp(line, username) != 0) {
            continue;
        }

        hash = separator + 1;
        hashLen = strcspn(hash, "\r\n");
        hash[hashLen] = '\0';

        if (hashLen >= CADMUS_HASH_HEX_LEN) {
            fclose(fptr);
            return CADMUS_ERR_OVERFLOW;
        }

        memcpy(hash_out, hash, hashLen + 1);
        fclose(fptr);
        return CADMUS_OK;
    }

    fclose(fptr);
    return CADMUS_ERR_USER_NOT_FOUND;
}
