#include "../include/edoc.h"
#include "../include/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_u16_le(cadmus_u8 *dst, cadmus_u16 value);
static void write_u32_le(cadmus_u8 *dst, cadmus_u32 value);
static cadmus_u16 read_u16_le(const cadmus_u8 *src);
static cadmus_u32 read_u32_le(const cadmus_u8 *src);
static void edoc_serialize_internal(const EdocHeader *header,
                                    cadmus_u8 buf[EDOC_HEADER_SIZE],
                                    int zero_header_checksum);

void edoc_sign_header(EdocHeader *header, const cadmus_u8 key[CADMUS_KEY_LEN]) {
    cadmus_u8 buf[EDOC_HEADER_SIZE];

    if (header == NULL || key == NULL) {
        return;
    }

    edoc_serialize_internal(header, buf, 1);
    header->header_checksum = crypto_keyed_checksum32(key, buf, EDOC_HEADER_SIZE);
    crypto_secure_zero(buf, sizeof(buf));
}

CadmusError edoc_verify_header(const EdocHeader *header, const cadmus_u8 key[CADMUS_KEY_LEN]) {
    cadmus_u8 buf[EDOC_HEADER_SIZE];
    cadmus_u32 expected;

    if (header == NULL || key == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    edoc_serialize_internal(header, buf, 1);
    expected = crypto_keyed_checksum32(key, buf, EDOC_HEADER_SIZE);
    crypto_secure_zero(buf, sizeof(buf));
    return expected == header->header_checksum ? CADMUS_OK : CADMUS_ERR_INVALID_SIGNATURE;
}

void edoc_serialize_header(const EdocHeader *header, cadmus_u8 buf[EDOC_HEADER_SIZE]) {
    if (header == NULL || buf == NULL) {
        return;
    }

    edoc_serialize_internal(header, buf, 0);
}

CadmusError edoc_deserialize_header(const cadmus_u8 buf[EDOC_HEADER_SIZE], EdocHeader *out) {
    cadmus_u32 i;
    cadmus_u32 offset = 0;

    if (buf == NULL || out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->magic, buf + offset, 4);
    offset += 4;
    out->version = read_u16_le(buf + offset);
    offset += 2;
    memcpy(out->owner_id, buf + offset, CADMUS_USERNAME_MAX);
    out->owner_id[CADMUS_USERNAME_MAX - 1] = '\0';
    offset += CADMUS_USERNAME_MAX;
    memcpy(out->doc_id, buf + offset, CADMUS_DOC_ID_LEN);
    offset += CADMUS_DOC_ID_LEN;
    memcpy(out->original_filename, buf + offset, CADMUS_FILENAME_MAX);
    out->original_filename[CADMUS_FILENAME_MAX - 1] = '\0';
    offset += CADMUS_FILENAME_MAX;
    out->payload_checksum = read_u32_le(buf + offset);
    offset += 4;
    out->header_checksum = read_u32_le(buf + offset);
    offset += 4;
    out->payload_len = read_u32_le(buf + offset);
    offset += 4;
    out->plain_len = read_u32_le(buf + offset);
    offset += 4;
    out->compression = buf[offset++];
    out->acl_count = read_u32_le(buf + offset);
    offset += 4;

    if (out->magic[0] != EDOC_MAGIC_0 || out->magic[1] != EDOC_MAGIC_1 ||
        out->magic[2] != EDOC_MAGIC_2 || out->magic[3] != EDOC_MAGIC_3 ||
        out->version != EDOC_VERSION || out->acl_count > CADMUS_MAX_ACL ||
        (out->compression != CADMUS_COMPRESS_NONE && out->compression != CADMUS_COMPRESS_RLE)) {
        return CADMUS_ERR_TAMPERED;
    }

    for (i = 0; i < CADMUS_MAX_ACL; i++) {
        memcpy(out->acl[i].username, buf + offset, CADMUS_USERNAME_MAX);
        out->acl[i].username[CADMUS_USERNAME_MAX - 1] = '\0';
        offset += CADMUS_USERNAME_MAX;
        out->acl[i].permissions = buf[offset++];
        memcpy(out->acl[i].granted_by, buf + offset, CADMUS_USERNAME_MAX);
        out->acl[i].granted_by[CADMUS_USERNAME_MAX - 1] = '\0';
        offset += CADMUS_USERNAME_MAX;
        memcpy(out->acl[i].wrapped_key, buf + offset, CADMUS_KEY_LEN);
        offset += CADMUS_KEY_LEN;
    }

    return CADMUS_OK;
}

CadmusError edoc_write(const char *path, const EdocHeader *header, const cadmus_u8 *payload, cadmus_u32 payload_len) {
    FILE *fptr;
    cadmus_u8 buf[EDOC_HEADER_SIZE];

    if (path == NULL || header == NULL || (payload == NULL && payload_len != 0)) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    fptr = fopen(path, "wb");
    if (fptr == NULL) {
        return CADMUS_ERR_FILE_IO;
    }

    edoc_serialize_header(header, buf);
    if (fwrite(buf, 1, sizeof(buf), fptr) != sizeof(buf) ||
        (payload_len != 0 && fwrite(payload, 1, (size_t)payload_len, fptr) != (size_t)payload_len)) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }

    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }

    return CADMUS_OK;
}

CadmusError edoc_read_header(const char *path, EdocHeader *out) {
    FILE *fptr;
    cadmus_u8 buf[EDOC_HEADER_SIZE];

    if (path == NULL || out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    fptr = fopen(path, "rb");
    if (fptr == NULL) {
        return CADMUS_ERR_NOT_FOUND;
    }

    if (fread(buf, 1, sizeof(buf), fptr) != sizeof(buf)) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }

    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }

    return edoc_deserialize_header(buf, out);
}

CadmusError edoc_read_payload(const char *path, const EdocHeader *header, cadmus_u8 **payload_out, cadmus_u32 *payload_len_out) {
    FILE *fptr;
    cadmus_u8 *payload;

    if (path == NULL || header == NULL || payload_out == NULL || payload_len_out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    *payload_out = NULL;
    *payload_len_out = 0;

    fptr = fopen(path, "rb");
    if (fptr == NULL) {
        return CADMUS_ERR_NOT_FOUND;
    }

    if (fseek(fptr, EDOC_HEADER_SIZE, SEEK_SET) != 0) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }

    if (header->payload_len == 0) {
        fclose(fptr);
        return CADMUS_OK;
    }

    payload = (cadmus_u8 *)malloc(header->payload_len);
    if (payload == NULL) {
        fclose(fptr);
        return CADMUS_ERR_ALLOC;
    }

    if (fread(payload, 1, (size_t)header->payload_len, fptr) != (size_t)header->payload_len) {
        free(payload);
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }

    if (fclose(fptr) != 0) {
        free(payload);
        return CADMUS_ERR_FILE_IO;
    }

    *payload_out = payload;
    *payload_len_out = header->payload_len;
    return CADMUS_OK;
}

CadmusError edoc_update_header(const char *path, const EdocHeader *header) {
    FILE *fptr;
    cadmus_u8 buf[EDOC_HEADER_SIZE];

    if (path == NULL || header == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    fptr = fopen(path, "r+b");
    if (fptr == NULL) {
        return CADMUS_ERR_NOT_FOUND;
    }

    edoc_serialize_header(header, buf);
    if (fwrite(buf, 1, sizeof(buf), fptr) != sizeof(buf)) {
        fclose(fptr);
        return CADMUS_ERR_FILE_IO;
    }

    if (fclose(fptr) != 0) {
        return CADMUS_ERR_FILE_IO;
    }

    return CADMUS_OK;
}

CadmusError edoc_build_path(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN], char path_out[CADMUS_PATH_MAX]) {
    char doc_id_str[CADMUS_DOC_ID_STR_LEN];
    int written;

    if (doc_id == NULL || path_out == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    crypto_doc_id_to_str(doc_id, doc_id_str);
    written = snprintf(path_out, CADMUS_PATH_MAX, "%s_%s.edoc", CADMUS_DOC_PREFIX, doc_id_str);
    if (written < 0 || written >= CADMUS_PATH_MAX) {
        return CADMUS_ERR_OVERFLOW;
    }
    return CADMUS_OK;
}

static void write_u16_le(cadmus_u8 *dst, cadmus_u16 value) {
    dst[0] = (cadmus_u8)(value & 0xffu);
    dst[1] = (cadmus_u8)((value >> 8) & 0xffu);
}

static void write_u32_le(cadmus_u8 *dst, cadmus_u32 value) {
    dst[0] = (cadmus_u8)(value & 0xffu);
    dst[1] = (cadmus_u8)((value >> 8) & 0xffu);
    dst[2] = (cadmus_u8)((value >> 16) & 0xffu);
    dst[3] = (cadmus_u8)((value >> 24) & 0xffu);
}

static cadmus_u16 read_u16_le(const cadmus_u8 *src) {
    return (cadmus_u16)src[0] | (cadmus_u16)((cadmus_u16)src[1] << 8);
}

static cadmus_u32 read_u32_le(const cadmus_u8 *src) {
    return (cadmus_u32)src[0] |
           ((cadmus_u32)src[1] << 8) |
           ((cadmus_u32)src[2] << 16) |
           ((cadmus_u32)src[3] << 24);
}

static void edoc_serialize_internal(const EdocHeader *header,
                                    cadmus_u8 buf[EDOC_HEADER_SIZE],
                                    int zero_header_checksum) {
    cadmus_u32 i;
    cadmus_u32 offset = 0;

    memset(buf, 0, EDOC_HEADER_SIZE);
    memcpy(buf + offset, header->magic, 4);
    offset += 4;
    write_u16_le(buf + offset, header->version);
    offset += 2;
    memcpy(buf + offset, header->owner_id, CADMUS_USERNAME_MAX);
    offset += CADMUS_USERNAME_MAX;
    memcpy(buf + offset, header->doc_id, CADMUS_DOC_ID_LEN);
    offset += CADMUS_DOC_ID_LEN;
    memcpy(buf + offset, header->original_filename, CADMUS_FILENAME_MAX);
    offset += CADMUS_FILENAME_MAX;
    write_u32_le(buf + offset, header->payload_checksum);
    offset += 4;
    write_u32_le(buf + offset, zero_header_checksum ? 0u : header->header_checksum);
    offset += 4;
    write_u32_le(buf + offset, header->payload_len);
    offset += 4;
    write_u32_le(buf + offset, header->plain_len);
    offset += 4;
    buf[offset++] = header->compression;
    write_u32_le(buf + offset, header->acl_count);
    offset += 4;

    for (i = 0; i < CADMUS_MAX_ACL; i++) {
        memcpy(buf + offset, header->acl[i].username, CADMUS_USERNAME_MAX);
        offset += CADMUS_USERNAME_MAX;
        buf[offset++] = header->acl[i].permissions;
        memcpy(buf + offset, header->acl[i].granted_by, CADMUS_USERNAME_MAX);
        offset += CADMUS_USERNAME_MAX;
        memcpy(buf + offset, header->acl[i].wrapped_key, CADMUS_KEY_LEN);
        offset += CADMUS_KEY_LEN;
    }
}
