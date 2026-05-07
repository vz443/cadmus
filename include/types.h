#ifndef CADMUS_TYPES_H
#define CADMUS_TYPES_H

typedef unsigned char  cadmus_u8;
typedef unsigned short cadmus_u16;
typedef unsigned int   cadmus_u32;

#define CADMUS_USERNAME_MAX   64
#define CADMUS_FILENAME_MAX   256
#define CADMUS_KEY_LEN        32
#define CADMUS_SHA256_LEN     32
#define CADMUS_HMAC_LEN       32
#define CADMUS_NONCE_LEN      12
#define CADMUS_DOC_ID_LEN     16
#define CADMUS_DOC_ID_STR_LEN 37
#define CADMUS_MAX_ACL        32
#define CADMUS_PATH_MAX       512

#define CADMUS_ACL_ENTRY_SIZE   133
#define EDOC_HEADER_SIGNED_SIZE 4658
#define EDOC_HEADER_SIZE        4690

#define CADMUS_PERM_READ   0x01u
#define CADMUS_PERM_WRITE  0x02u
#define CADMUS_PERM_SHARE  0x04u
#define CADMUS_PERM_DELETE 0x08u
#define CADMUS_PERM_ALL    0x0Fu

#define CADMUS_DIR_NAME     ".cadmus"
#define CADMUS_STORE_DIR    "store"
#define CADMUS_SESSION_FILE "session-key"
#define CADMUS_USERS_FILE   "users"

typedef enum CadmusError {
    CADMUS_OK                      = 0,
    CADMUS_ERR_NOT_FOUND           = 1,
    CADMUS_ERR_PERMISSION_DENIED   = 2,
    CADMUS_ERR_INVALID_SIGNATURE   = 3,
    CADMUS_ERR_EXPIRED             = 4,
    CADMUS_ERR_NOT_AUTHENTICATED   = 5,
    CADMUS_ERR_FILE_IO             = 6,
    CADMUS_ERR_INVALID_ARGS        = 7,
    CADMUS_ERR_USER_EXISTS         = 8,
    CADMUS_ERR_INVALID_CREDENTIALS = 9,
    CADMUS_ERR_TAMPERED            = 10,
    CADMUS_ERR_ALLOC               = 11,
    CADMUS_ERR_OVERFLOW            = 12,
    CADMUS_ERR_USER_NOT_FOUND      = 13
} CadmusError;

#endif /* CADMUS_TYPES_H */
