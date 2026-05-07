#ifndef CADMUS_EDOC_H
#define CADMUS_EDOC_H

/* Assigned to: Varen */

#include "types.h"
#include "crypto.h"

#define EDOC_MAGIC_0 0x45u
#define EDOC_MAGIC_1 0x44u
#define EDOC_MAGIC_2 0x4Fu
#define EDOC_MAGIC_3 0x43u
#define EDOC_VERSION 1

typedef struct {
    char       username[CADMUS_USERNAME_MAX];
    cadmus_u8  permissions;
    cadmus_u32 expires;
    char       granted_by[CADMUS_USERNAME_MAX];
    cadmus_u8  encrypted_dek[CADMUS_KEY_LEN];
} AclEntry;

typedef struct {
    cadmus_u8  magic[4];
    cadmus_u16 version;
    char       owner_id[CADMUS_USERNAME_MAX];
    cadmus_u8  doc_id[CADMUS_DOC_ID_LEN];
    cadmus_u32 created_at;
    cadmus_u32 modified_at;
    char       original_filename[CADMUS_FILENAME_MAX];
    cadmus_u8  payload_sha[CADMUS_SHA256_LEN];
    cadmus_u8  nonce[CADMUS_NONCE_LEN];
    cadmus_u32 payload_len;
    cadmus_u32 acl_count;
    AclEntry   acl[CADMUS_MAX_ACL];
    cadmus_u8  hmac[CADMUS_HMAC_LEN];
} EdocHeader;

/* Varen */
void edoc_sign_header(EdocHeader *header,
                      const cadmus_u8 key[CADMUS_KEY_LEN]);

/* Varen */
CadmusError edoc_verify_header(const EdocHeader *header,
                                const cadmus_u8 key[CADMUS_KEY_LEN]);

/* Varen */
void edoc_serialize_header(const EdocHeader *header,
                            cadmus_u8 buf[EDOC_HEADER_SIZE]);

/* Varen */
CadmusError edoc_deserialize_header(const cadmus_u8 buf[EDOC_HEADER_SIZE],
                                     EdocHeader *out);

/* Varen */
CadmusError edoc_write(const char *path,
                        const EdocHeader *header,
                        const cadmus_u8 *payload,
                        cadmus_u32 payload_len);

/* Varen */
CadmusError edoc_read_header(const char *path, EdocHeader *out);

/* Varen */
CadmusError edoc_read_payload(const char *path,
                               const EdocHeader *header,
                               cadmus_u8 **payload_out,
                               cadmus_u32 *payload_len_out);

/* Varen */
CadmusError edoc_update_header(const char *path, const EdocHeader *header);

/* Varen */
CadmusError edoc_build_path(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                             char path_out[CADMUS_PATH_MAX]);

#endif /* CADMUS_EDOC_H */
