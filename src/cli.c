#include "../include/auth.h"
#include "../include/cli.h"
#include "../include/compression.h"
#include "../include/crypto.h"
#include "../include/edoc.h"
#include "../include/kms.h"
#include "../include/logger.h"
#include "../include/pdp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLI_MAX_ARGS 64
#define CLI_PASSWORD_MAX 256
#define CLI_INDEX_LINE_MAX 512
#define CLI_USER_HASH_MAX 128

static CadmusError cli_require_session(char username[CADMUS_USERNAME_MAX], cadmus_u8 key[CADMUS_KEY_LEN]);
static CadmusError cli_read_file_bytes(const char *path, cadmus_u8 **data_out, cadmus_u32 *len_out);
static CadmusError cli_lookup_user_hash(const char *username, char *hash_out, int hash_out_len);
static CadmusError cli_get_doc_key_for_user(const EdocHeader *header,
                                            const char *username,
                                            const cadmus_u8 session_key[CADMUS_KEY_LEN],
                                            cadmus_u8 doc_key_out[CADMUS_KEY_LEN]);
static CadmusError cli_load_doc_for_user(const char *doc_id_str,
                                         const char *username,
                                         const cadmus_u8 session_key[CADMUS_KEY_LEN],
                                         EdocHeader *header,
                                         cadmus_u8 doc_key_out[CADMUS_KEY_LEN],
                                         char path_out[CADMUS_PATH_MAX]);
static CadmusError cli_next_doc_id(cadmus_u8 doc_id_out[CADMUS_DOC_ID_LEN]);
static CadmusError cli_add_index_entry(const EdocHeader *header);
static CadmusError cli_remove_index_entry(const char *doc_id_str);
static AclEntry *cli_find_acl_entry(EdocHeader *header, const char *username);
static const AclEntry *cli_find_acl_entry_const(const EdocHeader *header, const char *username);
static void cli_wrap_key(const cadmus_u8 wrapping_key[CADMUS_KEY_LEN],
                         const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                         const cadmus_u8 plain_key[CADMUS_KEY_LEN],
                         cadmus_u8 out[CADMUS_KEY_LEN]);
static const char *cli_basename(const char *path);
static int cli_invalid_metadata_field(const char *value);
static cadmus_u32 cli_doc_id_value(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]);
static int cli_file_exists(const char *path);

CadmusError cli_dispatch(int argc, char *argv[]) {
    char *args[CLI_MAX_ARGS];
    int arg_count = 0;
    int i;
    CadmusError err;
    const char *context = NULL;

    logger_set_level(LOG_WARN);
    if (argc > CLI_MAX_ARGS) {
        cli_print_error(CADMUS_ERR_INVALID_ARGS, "arguments");
        return CADMUS_ERR_INVALID_ARGS;
    }

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            logger_set_level(LOG_DEBUG);
            continue;
        }
        args[arg_count++] = argv[i];
    }

    if (arg_count < 2 || strcmp(args[1], "-h") == 0 || strcmp(args[1], "--help") == 0) {
        cli_help();
        return CADMUS_OK;
    }

    if (strcmp(args[1], "auth") == 0) {
        if (arg_count < 3) {
            cli_help_auth();
            return CADMUS_ERR_INVALID_ARGS;
        }
        if (strcmp(args[2], "register") == 0) {
            context = "auth register";
            err = cmd_auth_register(arg_count, args);
        } else if (strcmp(args[2], "login") == 0) {
            context = "auth login";
            err = cmd_auth_login(arg_count, args);
        } else if (strcmp(args[2], "logout") == 0) {
            context = "auth logout";
            err = cmd_auth_logout(arg_count, args);
        } else {
            cli_help_auth();
            return CADMUS_ERR_INVALID_ARGS;
        }
    } else if (strcmp(args[1], "file") == 0) {
        if (arg_count < 3) {
            cli_help_file();
            return CADMUS_ERR_INVALID_ARGS;
        }
        if (strcmp(args[2], "upload") == 0) {
            context = "file upload";
            err = cmd_file_upload(arg_count, args);
        } else if (strcmp(args[2], "read") == 0) {
            context = "file read";
            err = cmd_file_read(arg_count, args);
        } else if (strcmp(args[2], "share") == 0) {
            context = "file share";
            err = cmd_file_share(arg_count, args);
        } else if (strcmp(args[2], "list") == 0) {
            context = "file list";
            err = cmd_file_list(arg_count, args);
        } else if (strcmp(args[2], "delete") == 0) {
            context = "file delete";
            err = cmd_file_delete(arg_count, args);
        } else {
            cli_help_file();
            return CADMUS_ERR_INVALID_ARGS;
        }
    } else {
        cli_help();
        return CADMUS_ERR_INVALID_ARGS;
    }

    if (err != CADMUS_OK) {
        cli_print_error(err, context);
    }
    return err;
}

void cli_help(void) {
    printf("Usage:\n");
    printf("  cadmus auth register <username>\n");
    printf("  cadmus auth login <username>\n");
    printf("  cadmus auth logout\n");
    printf("  cadmus file upload <filepath> [-d]\n");
    printf("  cadmus file read <doc_id>\n");
    printf("  cadmus file share <doc_id> <username> --permission <perms>\n");
    printf("  cadmus file list\n");
    printf("  cadmus file delete <doc_id>\n");
}

void cli_help_auth(void) {
    printf("Auth commands:\n");
    printf("  cadmus auth register <username>\n");
    printf("  cadmus auth login <username>\n");
    printf("  cadmus auth logout\n");
}

void cli_help_file(void) {
    printf("File commands:\n");
    printf("  cadmus file upload <filepath> [-d]\n");
    printf("  cadmus file read <doc_id>\n");
    printf("  cadmus file share <doc_id> <username> --permission <perms>\n");
    printf("  cadmus file list\n");
    printf("  cadmus file delete <doc_id>\n");
}

CadmusError cmd_auth_register(int argc, char *argv[]) {
    char password[CLI_PASSWORD_MAX];
    CadmusError err;

    if (argc != 4) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    cli_read_password("password: ", password, sizeof(password));
    err = auth_register(argv[3], password);
    crypto_secure_zero(password, sizeof(password));
    if (err == CADMUS_OK) {
        printf("registered %s\n", argv[3]);
    }
    return err;
}

CadmusError cmd_auth_login(int argc, char *argv[]) {
    char password[CLI_PASSWORD_MAX];
    CadmusError err;

    if (argc != 4) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    cli_read_password("password: ", password, sizeof(password));
    err = auth_login(argv[3], password);
    crypto_secure_zero(password, sizeof(password));
    if (err == CADMUS_OK) {
        printf("logged in as %s\n", argv[3]);
    }
    return err;
}

CadmusError cmd_auth_logout(int argc, char *argv[]) {
    CadmusError err;
    (void)argv;

    if (argc != 3) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    err = auth_logout();
    if (err == CADMUS_OK) {
        printf("logged out\n");
    }
    return err;
}

CadmusError cmd_file_upload(int argc, char *argv[]) {
    char username[CADMUS_USERNAME_MAX];
    cadmus_u8 session_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 doc_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 *plain = NULL;
    cadmus_u8 *packed = NULL;
    cadmus_u8 *cipher = NULL;
    const cadmus_u8 *payload_in = NULL;
    cadmus_u32 plain_len = 0;
    cadmus_u32 packed_len = 0;
    cadmus_u32 payload_len = 0;
    char path[CADMUS_PATH_MAX];
    char doc_id_str[CADMUS_DOC_ID_STR_LEN];
    const char *filename;
    EdocHeader header;
    CadmusError err;
    int delete_original = 0;
    int i;

    if (argc < 4) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    for (i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            delete_original = 1;
        } else {
            return CADMUS_ERR_INVALID_ARGS;
        }
    }

    filename = cli_basename(argv[3]);
    if (cli_invalid_metadata_field(filename) || strlen(filename) >= CADMUS_FILENAME_MAX) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    err = cli_require_session(username, session_key);
    if (err != CADMUS_OK) {
        return err;
    }
    err = cli_read_file_bytes(argv[3], &plain, &plain_len);
    if (err != CADMUS_OK) {
        crypto_secure_zero(session_key, sizeof(session_key));
        return err;
    }
    err = compression_rle_compress(plain, plain_len, &packed, &packed_len);
    if (err != CADMUS_OK) {
        crypto_secure_zero(session_key, sizeof(session_key));
        crypto_secure_zero(plain, plain_len);
        free(plain);
        return err;
    }

    memset(&header, 0, sizeof(header));
    header.magic[0] = EDOC_MAGIC_0;
    header.magic[1] = EDOC_MAGIC_1;
    header.magic[2] = EDOC_MAGIC_2;
    header.magic[3] = EDOC_MAGIC_3;
    header.version = EDOC_VERSION;
    strncpy(header.owner_id, username, CADMUS_USERNAME_MAX - 1);
    strncpy(header.original_filename, filename, CADMUS_FILENAME_MAX - 1);
    header.plain_len = plain_len;
    header.acl_count = 1;
    strncpy(header.acl[0].username, username, CADMUS_USERNAME_MAX - 1);
    header.acl[0].permissions = CADMUS_PERM_ALL;
    strncpy(header.acl[0].granted_by, username, CADMUS_USERNAME_MAX - 1);

    err = cli_next_doc_id(header.doc_id);
    if (err == CADMUS_OK) {
        crypto_derive_doc_key(session_key, header.doc_id, doc_key);
        cli_wrap_key(session_key, header.doc_id, doc_key, header.acl[0].wrapped_key);
    }

    if (err == CADMUS_OK) {
        if (packed != NULL && packed_len < plain_len) {
            header.compression = CADMUS_COMPRESS_RLE;
            payload_in = packed;
            payload_len = packed_len;
        } else {
            header.compression = CADMUS_COMPRESS_NONE;
            payload_in = plain;
            payload_len = plain_len;
        }
        header.payload_len = payload_len;
    }

    if (err == CADMUS_OK && payload_len != 0) {
        cipher = (cadmus_u8 *)malloc(payload_len);
        if (cipher == NULL) {
            err = CADMUS_ERR_ALLOC;
        } else {
            crypto_xor_stream(doc_key, header.doc_id, payload_in, cipher, payload_len);
        }
    }

    if (err == CADMUS_OK) {
        header.payload_checksum = crypto_checksum32(cipher, payload_len);
        edoc_sign_header(&header, doc_key);
        err = edoc_build_path(header.doc_id, path);
    }
    if (err == CADMUS_OK) {
        err = edoc_write(path, &header, cipher, payload_len);
    }
    if (err == CADMUS_OK) {
        err = cli_add_index_entry(&header);
        if (err != CADMUS_OK) {
            remove(path);
        }
    }
    if (err == CADMUS_OK && delete_original && remove(argv[3]) != 0) {
        err = CADMUS_ERR_FILE_IO;
    }

    if (err == CADMUS_OK) {
        crypto_doc_id_to_str(header.doc_id, doc_id_str);
        printf("%s\n", doc_id_str);
    }

    if (plain != NULL) {
        crypto_secure_zero(plain, plain_len);
        free(plain);
    }
    if (packed != NULL) {
        crypto_secure_zero(packed, packed_len);
        free(packed);
    }
    if (cipher != NULL) {
        crypto_secure_zero(cipher, payload_len);
        free(cipher);
    }
    crypto_secure_zero(session_key, sizeof(session_key));
    crypto_secure_zero(doc_key, sizeof(doc_key));
    return err;
}

CadmusError cmd_file_read(int argc, char *argv[]) {
    char username[CADMUS_USERNAME_MAX];
    cadmus_u8 session_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 doc_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 *cipher = NULL;
    cadmus_u8 *plain = NULL;
    cadmus_u8 *decoded = NULL;
    cadmus_u32 cipher_len = 0;
    cadmus_u32 decoded_len = 0;
    char path[CADMUS_PATH_MAX];
    EdocHeader header;
    CadmusError err;

    if (argc != 4) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    err = cli_require_session(username, session_key);
    if (err != CADMUS_OK) {
        return err;
    }
    err = cli_load_doc_for_user(argv[3], username, session_key, &header, doc_key, path);
    if (err == CADMUS_OK) {
        err = pdp_check(&header, username, CADMUS_PERM_READ);
    }
    if (err == CADMUS_OK) {
        err = edoc_read_payload(path, &header, &cipher, &cipher_len);
    }
    if (err == CADMUS_OK && crypto_checksum32(cipher, cipher_len) != header.payload_checksum) {
        err = CADMUS_ERR_TAMPERED;
    }
    if (err == CADMUS_OK && cipher_len != 0) {
        plain = (cadmus_u8 *)malloc(cipher_len);
        if (plain == NULL) {
            err = CADMUS_ERR_ALLOC;
        } else {
            crypto_xor_stream(doc_key, header.doc_id, cipher, plain, cipher_len);
        }
    }
    if (err == CADMUS_OK) {
        if (header.compression == CADMUS_COMPRESS_RLE) {
            err = compression_rle_decompress(plain, cipher_len, header.plain_len, &decoded, &decoded_len);
        } else if (header.compression == CADMUS_COMPRESS_NONE) {
            if (header.plain_len != cipher_len) {
                err = CADMUS_ERR_TAMPERED;
            } else {
                decoded = plain;
                decoded_len = cipher_len;
                plain = NULL;
            }
        } else {
            err = CADMUS_ERR_TAMPERED;
        }
    }
    if (err == CADMUS_OK && decoded_len != 0 &&
        fwrite(decoded, 1, (size_t)decoded_len, stdout) != (size_t)decoded_len) {
        err = CADMUS_ERR_FILE_IO;
    }

    if (plain != NULL) {
        crypto_secure_zero(plain, cipher_len);
        free(plain);
    }
    if (decoded != NULL) {
        crypto_secure_zero(decoded, decoded_len);
        free(decoded);
    }
    if (cipher != NULL) {
        crypto_secure_zero(cipher, cipher_len);
        free(cipher);
    }
    crypto_secure_zero(session_key, sizeof(session_key));
    crypto_secure_zero(doc_key, sizeof(doc_key));
    return err;
}

CadmusError cmd_file_share(int argc, char *argv[]) {
    char username[CADMUS_USERNAME_MAX];
    char target_hash[CLI_USER_HASH_MAX];
    cadmus_u8 session_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 doc_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 target_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 permissions = 0;
    char path[CADMUS_PATH_MAX];
    const char *permission_arg = NULL;
    EdocHeader header;
    AclEntry *target_entry;
    CadmusError err;
    int i;

    if (argc < 7) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    for (i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--permission") == 0 && i + 1 < argc) {
            permission_arg = argv[++i];
        } else {
            return CADMUS_ERR_INVALID_ARGS;
        }
    }
    if (permission_arg == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    err = cli_parse_permissions(permission_arg, &permissions);
    if (err != CADMUS_OK) {
        return err;
    }
    if (!auth_user_exists(argv[4])) {
        return CADMUS_ERR_USER_NOT_FOUND;
    }

    err = cli_require_session(username, session_key);
    if (err != CADMUS_OK) {
        return err;
    }
    err = cli_load_doc_for_user(argv[3], username, session_key, &header, doc_key, path);
    if (err == CADMUS_OK) {
        err = pdp_grant(&header, username, argv[4], permissions);
    }
    if (err == CADMUS_OK) {
        err = cli_lookup_user_hash(argv[4], target_hash, sizeof(target_hash));
    }
    if (err == CADMUS_OK) {
        kms_derive_key(target_hash, target_key);
        target_entry = cli_find_acl_entry(&header, argv[4]);
        if (target_entry == NULL) {
            err = CADMUS_ERR_NOT_FOUND;
        } else {
            cli_wrap_key(target_key, header.doc_id, doc_key, target_entry->wrapped_key);
            edoc_sign_header(&header, doc_key);
            err = edoc_update_header(path, &header);
        }
    }

    crypto_secure_zero(target_hash, sizeof(target_hash));
    crypto_secure_zero(target_key, sizeof(target_key));
    crypto_secure_zero(session_key, sizeof(session_key));
    crypto_secure_zero(doc_key, sizeof(doc_key));

    if (err == CADMUS_OK) {
        printf("shared %s with %s\n", argv[3], argv[4]);
    }
    return err;
}

CadmusError cmd_file_list(int argc, char *argv[]) {
    char username[CADMUS_USERNAME_MAX];
    cadmus_u8 session_key[CADMUS_KEY_LEN] = {0};
    FILE *fptr;
    char index_path[CADMUS_PATH_MAX];
    char line[CLI_INDEX_LINE_MAX];
    int printed = 0;
    CadmusError err;
    (void)argv;

    if (argc != 3) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    err = cli_require_session(username, session_key);
    if (err != CADMUS_OK) {
        return err;
    }
    if (kms_index_path(index_path, sizeof(index_path)) != CADMUS_OK) {
        crypto_secure_zero(session_key, sizeof(session_key));
        return CADMUS_ERR_OVERFLOW;
    }

    fptr = fopen(index_path, "r");
    if (fptr == NULL) {
        crypto_secure_zero(session_key, sizeof(session_key));
        printf("no documents\n");
        return CADMUS_OK;
    }

    while (fgets(line, sizeof(line), fptr) != NULL) {
        char *sep1;
        char *sep2;
        char doc_id_str[CADMUS_DOC_ID_STR_LEN];
        char path[CADMUS_PATH_MAX];
        cadmus_u8 doc_key[CADMUS_KEY_LEN] = {0};
        EdocHeader header;

        sep1 = strchr(line, ':');
        if (sep1 == NULL) {
            continue;
        }
        sep2 = strchr(sep1 + 1, ':');
        if (sep2 == NULL) {
            continue;
        }

        *sep1 = '\0';
        if (strlen(line) >= sizeof(doc_id_str)) {
            continue;
        }
        strcpy(doc_id_str, line);

        err = cli_load_doc_for_user(doc_id_str, username, session_key, &header, doc_key, path);
        if (err != CADMUS_OK) {
            crypto_secure_zero(doc_key, sizeof(doc_key));
            continue;
        }
        if (pdp_check(&header, username, 0) != CADMUS_OK) {
            crypto_secure_zero(doc_key, sizeof(doc_key));
            continue;
        }

        printf("%s  %s  %s\n", doc_id_str, header.owner_id, header.original_filename);
        printed = 1;
        crypto_secure_zero(doc_key, sizeof(doc_key));
    }

    fclose(fptr);
    crypto_secure_zero(session_key, sizeof(session_key));
    if (!printed) {
        printf("no documents\n");
    }
    return CADMUS_OK;
}

CadmusError cmd_file_delete(int argc, char *argv[]) {
    char username[CADMUS_USERNAME_MAX];
    cadmus_u8 session_key[CADMUS_KEY_LEN] = {0};
    cadmus_u8 doc_key[CADMUS_KEY_LEN] = {0};
    char path[CADMUS_PATH_MAX];
    EdocHeader header;
    CadmusError err;

    if (argc != 4) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    err = cli_require_session(username, session_key);
    if (err != CADMUS_OK) {
        return err;
    }
    err = cli_load_doc_for_user(argv[3], username, session_key, &header, doc_key, path);
    if (err == CADMUS_OK) {
        err = pdp_check(&header, username, CADMUS_PERM_DELETE);
    }
    if (err == CADMUS_OK && remove(path) != 0) {
        err = CADMUS_ERR_FILE_IO;
    }
    if (err == CADMUS_OK) {
        err = cli_remove_index_entry(argv[3]);
    }

    crypto_secure_zero(session_key, sizeof(session_key));
    crypto_secure_zero(doc_key, sizeof(doc_key));
    if (err == CADMUS_OK) {
        printf("deleted %s\n", argv[3]);
    }
    return err;
}

CadmusError cli_parse_permissions(const char *str, cadmus_u8 *perm_out) {
    char copy[64];
    char *token;
    cadmus_u8 permissions = 0;

    if (str == NULL || perm_out == NULL || strlen(str) >= sizeof(copy)) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    strcpy(copy, str);
    token = strtok(copy, ",");
    while (token != NULL) {
        if (strcmp(token, "read") == 0) {
            permissions |= CADMUS_PERM_READ;
        } else if (strcmp(token, "write") == 0) {
            permissions |= CADMUS_PERM_WRITE;
        } else if (strcmp(token, "share") == 0) {
            permissions |= CADMUS_PERM_SHARE;
        } else if (strcmp(token, "delete") == 0) {
            permissions |= CADMUS_PERM_DELETE;
        } else if (strcmp(token, "all") == 0) {
            permissions |= CADMUS_PERM_ALL;
        } else {
            return CADMUS_ERR_INVALID_ARGS;
        }
        token = strtok(NULL, ",");
    }

    if (permissions == 0) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    *perm_out = permissions;
    return CADMUS_OK;
}

void cli_read_password(const char *prompt, char *buf, int buf_len) {
    size_t len;

    if (buf == NULL || buf_len <= 1) {
        return;
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (fgets(buf, buf_len, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    len = strcspn(buf, "\r\n");
    buf[len] = '\0';
}

void cli_print_error(CadmusError err, const char *context) {
    if (context != NULL) {
        fprintf(stderr, "%s: ", context);
    }

    switch (err) {
        case CADMUS_OK:
            fprintf(stderr, "ok\n");
            break;
        case CADMUS_ERR_NOT_FOUND:
            fprintf(stderr, "not found\n");
            break;
        case CADMUS_ERR_PERMISSION_DENIED:
            fprintf(stderr, "permission denied\n");
            break;
        case CADMUS_ERR_INVALID_SIGNATURE:
            fprintf(stderr, "invalid signature\n");
            break;
        case CADMUS_ERR_NOT_AUTHENTICATED:
            fprintf(stderr, "not authenticated\n");
            break;
        case CADMUS_ERR_FILE_IO:
            fprintf(stderr, "file io error\n");
            break;
        case CADMUS_ERR_INVALID_ARGS:
            fprintf(stderr, "invalid arguments\n");
            break;
        case CADMUS_ERR_USER_EXISTS:
            fprintf(stderr, "user already exists\n");
            break;
        case CADMUS_ERR_INVALID_CREDENTIALS:
            fprintf(stderr, "invalid credentials\n");
            break;
        case CADMUS_ERR_TAMPERED:
            fprintf(stderr, "tampered data\n");
            break;
        case CADMUS_ERR_ALLOC:
            fprintf(stderr, "allocation failed\n");
            break;
        case CADMUS_ERR_OVERFLOW:
            fprintf(stderr, "buffer or capacity overflow\n");
            break;
        case CADMUS_ERR_USER_NOT_FOUND:
            fprintf(stderr, "user not found\n");
            break;
        default:
            fprintf(stderr, "unknown error\n");
            break;
    }
}

static CadmusError cli_require_session(char username[CADMUS_USERNAME_MAX], cadmus_u8 key[CADMUS_KEY_LEN]) {
    return kms_load_session(username, key);
}

static CadmusError cli_read_file_bytes(const char *path, cadmus_u8 **data_out, cadmus_u32 *len_out) {
    FILE *fptr;
    long size;
    cadmus_u8 *data = NULL;

    if (path == NULL || data_out == NULL || len_out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    *data_out = NULL;
    *len_out = 0;
    fptr = fopen(path, "rb");
    if (fptr == NULL) {
        return CADMUS_ERR_NOT_FOUND;
    }
    if (fseek(fptr, 0, SEEK_END) != 0) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }
    size = ftell(fptr);
    if (size < 0 || size > 0xffffffffL) {
        fclose(fptr);
        return CADMUS_ERR_OVERFLOW;
    }
    if (fseek(fptr, 0, SEEK_SET) != 0) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }
    if (size > 0) {
        data = (cadmus_u8 *)malloc((size_t)size);
        if (data == NULL) {
            fclose(fptr);
            return CADMUS_ERR_ALLOC;
        }
        if (fread(data, 1, (size_t)size, fptr) != (size_t)size) {
            free(data);
            fclose(fptr);
            return CADMUS_ERR_FILE_IO;
        }
    }
    if (fclose(fptr) != 0) {
        free(data);
        return CADMUS_ERR_FILE_IO;
    }
    *data_out = data;
    *len_out = (cadmus_u32)size;
    return CADMUS_OK;
}

static CadmusError cli_lookup_user_hash(const char *username, char *hash_out, int hash_out_len) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    char line[256];

    if (username == NULL || hash_out == NULL || hash_out_len <= 0) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    if (kms_users_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_OVERFLOW;
    }

    fptr = fopen(path, "r");
    if (fptr == NULL) {
        return CADMUS_ERR_FILE_IO;
    }

    while (fgets(line, sizeof(line), fptr) != NULL) {
        char *separator = strchr(line, ':');
        char *hash;
        size_t hash_len;

        if (separator == NULL) {
            continue;
        }
        *separator = '\0';
        if (strcmp(line, username) != 0) {
            continue;
        }

        hash = separator + 1;
        hash_len = strcspn(hash, "\r\n");
        if ((int)hash_len >= hash_out_len) {
            fclose(fptr);
            return CADMUS_ERR_OVERFLOW;
        }

        memcpy(hash_out, hash, hash_len);
        hash_out[hash_len] = '\0';
        fclose(fptr);
        return CADMUS_OK;
    }

    fclose(fptr);
    return CADMUS_ERR_USER_NOT_FOUND;
}

static CadmusError cli_get_doc_key_for_user(const EdocHeader *header,
                                            const char *username,
                                            const cadmus_u8 session_key[CADMUS_KEY_LEN],
                                            cadmus_u8 doc_key_out[CADMUS_KEY_LEN]) {
    const AclEntry *entry;

    if (header == NULL || username == NULL || session_key == NULL || doc_key_out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    entry = cli_find_acl_entry_const(header, username);
    if (entry == NULL) {
        return CADMUS_ERR_NOT_FOUND;
    }

    cli_wrap_key(session_key, header->doc_id, entry->wrapped_key, doc_key_out);
    return CADMUS_OK;
}

static CadmusError cli_load_doc_for_user(const char *doc_id_str,
                                         const char *username,
                                         const cadmus_u8 session_key[CADMUS_KEY_LEN],
                                         EdocHeader *header,
                                         cadmus_u8 doc_key_out[CADMUS_KEY_LEN],
                                         char path_out[CADMUS_PATH_MAX]) {
    cadmus_u8 doc_id[CADMUS_DOC_ID_LEN];
    CadmusError err;

    err = crypto_doc_id_from_str(doc_id_str, doc_id);
    if (err != CADMUS_OK) {
        return err;
    }
    err = edoc_build_path(doc_id, path_out);
    if (err != CADMUS_OK) {
        return err;
    }
    err = edoc_read_header(path_out, header);
    if (err != CADMUS_OK) {
        return err;
    }
    err = cli_get_doc_key_for_user(header, username, session_key, doc_key_out);
    if (err != CADMUS_OK) {
        return err;
    }
    return edoc_verify_header(header, doc_key_out);
}

static CadmusError cli_next_doc_id(cadmus_u8 doc_id_out[CADMUS_DOC_ID_LEN]) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    char line[CLI_INDEX_LINE_MAX];
    cadmus_u32 max_id = 0;

    if (doc_id_out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    if (kms_index_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_OVERFLOW;
    }

    fptr = fopen(path, "r");
    if (fptr != NULL) {
        while (fgets(line, sizeof(line), fptr) != NULL) {
            char *separator = strchr(line, ':');
            cadmus_u8 doc_id[CADMUS_DOC_ID_LEN];

            if (separator == NULL) {
                continue;
            }
            *separator = '\0';
            if (crypto_doc_id_from_str(line, doc_id) == CADMUS_OK) {
                cadmus_u32 value = cli_doc_id_value(doc_id);
                if (value > max_id) {
                    max_id = value;
                }
            }
        }
        fclose(fptr);
    }

    if (max_id == 0xffffffffu) {
        return CADMUS_ERR_OVERFLOW;
    }
    for (;;) {
        char doc_path[CADMUS_PATH_MAX];

        max_id++;
        crypto_make_doc_id(max_id, doc_id_out);
        if (edoc_build_path(doc_id_out, doc_path) != CADMUS_OK) {
            return CADMUS_ERR_OVERFLOW;
        }
        if (!cli_file_exists(doc_path)) {
            break;
        }
        if (max_id == 0xffffffffu) {
            return CADMUS_ERR_OVERFLOW;
        }
    }
    return CADMUS_OK;
}

static CadmusError cli_add_index_entry(const EdocHeader *header) {
    FILE *fptr;
    char path[CADMUS_PATH_MAX];
    char doc_id_str[CADMUS_DOC_ID_STR_LEN];

    if (header == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    if (kms_index_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_OVERFLOW;
    }

    fptr = fopen(path, "a");
    if (fptr == NULL) {
        return CADMUS_ERR_FILE_IO;
    }

    crypto_doc_id_to_str(header->doc_id, doc_id_str);
    if (fprintf(fptr, "%s:%s:%s\n", doc_id_str, header->owner_id, header->original_filename) < 0) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }
    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }
    return CADMUS_OK;
}

static CadmusError cli_remove_index_entry(const char *doc_id_str) {
    FILE *src;
    FILE *dst;
    char path[CADMUS_PATH_MAX];
    char tmp_path[CADMUS_PATH_MAX];
    char line[CLI_INDEX_LINE_MAX];
    int found = 0;

    if (doc_id_str == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }
    if (kms_index_path(path, sizeof(path)) != CADMUS_OK) {
        return CADMUS_ERR_OVERFLOW;
    }
    strcpy(tmp_path, "cadmus_index.tmp");

    src = fopen(path, "r");
    if (src == NULL) {
        return CADMUS_ERR_NOT_FOUND;
    }
    dst = fopen(tmp_path, "w");
    if (dst == NULL) {
        fclose(src);
        return CADMUS_ERR_FILE_IO;
    }

    while (fgets(line, sizeof(line), src) != NULL) {
        char copy[CLI_INDEX_LINE_MAX];
        char *separator;

        strcpy(copy, line);
        separator = strchr(copy, ':');
        if (separator != NULL) {
            *separator = '\0';
            if (strcmp(copy, doc_id_str) == 0) {
                found = 1;
                continue;
            }
        }
        if (fputs(line, dst) == EOF) {
            fclose(src);
            fclose(dst);
            remove(tmp_path);
            return CADMUS_ERR_FILE_IO;
        }
    }

    if (fclose(src) != 0 || fclose(dst) != 0) {
        remove(tmp_path);
        return CADMUS_ERR_FILE_IO;
    }
    if (!found) {
        remove(tmp_path);
        return CADMUS_ERR_NOT_FOUND;
    }
    if (rename(tmp_path, path) != 0) {
        remove(tmp_path);
        return CADMUS_ERR_FILE_IO;
    }
    return CADMUS_OK;
}

static AclEntry *cli_find_acl_entry(EdocHeader *header, const char *username) {
    cadmus_u32 i;

    if (header == NULL || username == NULL) {
        return NULL;
    }
    for (i = 0; i < header->acl_count && i < CADMUS_MAX_ACL; i++) {
        if (strcmp(header->acl[i].username, username) == 0) {
            return &header->acl[i];
        }
    }
    return NULL;
}

static const AclEntry *cli_find_acl_entry_const(const EdocHeader *header, const char *username) {
    cadmus_u32 i;

    if (header == NULL || username == NULL) {
        return NULL;
    }
    for (i = 0; i < header->acl_count && i < CADMUS_MAX_ACL; i++) {
        if (strcmp(header->acl[i].username, username) == 0) {
            return &header->acl[i];
        }
    }
    return NULL;
}

static void cli_wrap_key(const cadmus_u8 wrapping_key[CADMUS_KEY_LEN],
                         const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                         const cadmus_u8 plain_key[CADMUS_KEY_LEN],
                         cadmus_u8 out[CADMUS_KEY_LEN]) {
    crypto_xor_stream(wrapping_key, doc_id, plain_key, out, CADMUS_KEY_LEN);
}

static const char *cli_basename(const char *path) {
    const char *slash;

    if (path == NULL) {
        return "";
    }
    slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static int cli_invalid_metadata_field(const char *value) {
    if (value == NULL || value[0] == '\0') {
        return 1;
    }
    return strchr(value, ':') != NULL || strchr(value, '\n') != NULL || strchr(value, '\r') != NULL;
}

static cadmus_u32 cli_doc_id_value(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]) {
    return (cadmus_u32)doc_id[0] |
           ((cadmus_u32)doc_id[1] << 8) |
           ((cadmus_u32)doc_id[2] << 16) |
           ((cadmus_u32)doc_id[3] << 24);
}

static int cli_file_exists(const char *path) {
    FILE *fptr;

    if (path == NULL) {
        return 0;
    }

    fptr = fopen(path, "rb");
    if (fptr == NULL) {
        return 0;
    }
    fclose(fptr);
    return 1;
}

int main(int argc, char *argv[]) {
    CadmusError err = cli_dispatch(argc, argv);
    return err == CADMUS_OK ? 0 : 1;
}
