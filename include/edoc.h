#ifndef CADMUS_EDOC_H
#define CADMUS_EDOC_H

/* Encrypted document container format and file I/O helpers. */

#include "types.h"

#define EDOC_MAGIC_0 0x45u
#define EDOC_MAGIC_1 0x44u
#define EDOC_MAGIC_2 0x4Fu
#define EDOC_MAGIC_3 0x43u
#define EDOC_VERSION 3

typedef struct {
    char       username[CADMUS_USERNAME_MAX];
    cadmus_u8  permissions;
    char       granted_by[CADMUS_USERNAME_MAX];
    cadmus_u8  wrapped_key[CADMUS_KEY_LEN];
} AclEntry;

typedef struct {
    cadmus_u8  magic[4];
    cadmus_u16 version;
    char       owner_id[CADMUS_USERNAME_MAX];
    cadmus_u8  doc_id[CADMUS_DOC_ID_LEN];
    char       original_filename[CADMUS_FILENAME_MAX];
    cadmus_u32 payload_checksum;
    cadmus_u32 header_checksum;
    cadmus_u32 payload_len;
    cadmus_u32 plain_len;
    cadmus_u8  compression;
    cadmus_u32 acl_count;
    AclEntry   acl[CADMUS_MAX_ACL];
} EdocHeader;

/* Recompute and store the header checksum. */
void edoc_sign_header(EdocHeader *header,
                      const cadmus_u8 key[CADMUS_KEY_LEN]);

/* Verify the header checksum and basic header fields. */
CadmusError edoc_verify_header(const EdocHeader *header,
                                const cadmus_u8 key[CADMUS_KEY_LEN]);

/* Serialize a header into its fixed-size on-disk representation. */
void edoc_serialize_header(const EdocHeader *header,
                            cadmus_u8 buf[EDOC_HEADER_SIZE]);

/* Parse a fixed-size on-disk header into an EdocHeader. */
CadmusError edoc_deserialize_header(const cadmus_u8 buf[EDOC_HEADER_SIZE],
                                     EdocHeader *out);

/* Write a header and payload to an .edoc file. */
CadmusError edoc_write(const char *path,
                        const EdocHeader *header,
                        const cadmus_u8 *payload,
                        cadmus_u32 payload_len);

/* Read only the header from an .edoc file. */
CadmusError edoc_read_header(const char *path, EdocHeader *out);

/* Read the payload bytes that follow a validated header. */
CadmusError edoc_read_payload(const char *path,
                               const EdocHeader *header,
                               cadmus_u8 **payload_out,
                               cadmus_u32 *payload_len_out);

/* Overwrite the header portion of an existing .edoc file. */
CadmusError edoc_update_header(const char *path, const EdocHeader *header);

/* Build the storage path for a document ID. */
CadmusError edoc_build_path(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                             char path_out[CADMUS_PATH_MAX]);

#endif /* CADMUS_EDOC_H */
