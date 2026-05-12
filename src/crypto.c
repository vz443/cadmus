#include "../include/crypto.h"
#include <string.h>

static cadmus_u32 crypto_seed_from_bytes(const cadmus_u8 *data, cadmus_u32 len);
static cadmus_u32 crypto_doc_id_value(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]);
static int crypto_hex_value(int c);

void crypto_mix_bytes(const cadmus_u8 *seed, cadmus_u32 seed_len, cadmus_u8 key_out[CADMUS_KEY_LEN]) {
    cadmus_u32 state;
    cadmus_u32 i;

    if (key_out == NULL) {
        return;
    }

    state = crypto_seed_from_bytes(seed, seed_len);
    for (i = 0; i < CADMUS_KEY_LEN; i++) {
        cadmus_u32 extra = seed_len == 0 ? i : seed[i % seed_len];
        state = state * 1664525u + 1013904223u + extra + (i * 97u);
        key_out[i] = (cadmus_u8)((state >> ((i & 3u) * 8u)) & 0xffu);
        state ^= (cadmus_u32)(key_out[i] + i);
    }
}

void crypto_derive_doc_key(const cadmus_u8 session_key[CADMUS_KEY_LEN],
                           const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                           cadmus_u8 doc_key_out[CADMUS_KEY_LEN]) {
    cadmus_u8 seed[CADMUS_KEY_LEN + CADMUS_DOC_ID_LEN];

    if (session_key == NULL || doc_id == NULL || doc_key_out == NULL) {
        return;
    }

    memcpy(seed, session_key, CADMUS_KEY_LEN);
    memcpy(seed + CADMUS_KEY_LEN, doc_id, CADMUS_DOC_ID_LEN);
    crypto_mix_bytes(seed, sizeof(seed), doc_key_out);
    crypto_secure_zero(seed, sizeof(seed));
}

void crypto_xor_stream(const cadmus_u8 key[CADMUS_KEY_LEN],
                       const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                       const cadmus_u8 *in,
                       cadmus_u8 *out,
                       cadmus_u32 len) {
    cadmus_u32 state;
    cadmus_u32 i;

    if (key == NULL || doc_id == NULL || (in == NULL && len != 0) || (out == NULL && len != 0)) {
        return;
    }

    state = crypto_seed_from_bytes(key, CADMUS_KEY_LEN) ^ crypto_doc_id_value(doc_id);
    for (i = 0; i < len; i++) {
        state = state * 22695477u + 1u + key[i % CADMUS_KEY_LEN] + doc_id[i % CADMUS_DOC_ID_LEN];
        out[i] = (cadmus_u8)(in[i] ^ (cadmus_u8)((state >> 24) & 0xffu));
        state ^= (cadmus_u32)(key[(i + 7u) % CADMUS_KEY_LEN] << 8);
    }
}

cadmus_u32 crypto_checksum32(const cadmus_u8 *data, cadmus_u32 len) {
    cadmus_u32 state = 0x13579bdfu;
    cadmus_u32 i;

    if (data == NULL && len != 0) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        state = (state * 33u) ^ data[i] ^ (state >> 13);
    }
    return state;
}

cadmus_u32 crypto_keyed_checksum32(const cadmus_u8 key[CADMUS_KEY_LEN],
                                   const cadmus_u8 *data,
                                   cadmus_u32 len) {
    cadmus_u32 state;
    cadmus_u32 i;

    if (key == NULL || (data == NULL && len != 0)) {
        return 0;
    }

    state = crypto_seed_from_bytes(key, CADMUS_KEY_LEN) ^ 0xa5a5a5a5u;
    for (i = 0; i < len; i++) {
        state = (state * 65599u) + data[i] + key[i % CADMUS_KEY_LEN];
        state ^= state >> 11;
    }
    return state;
}

void crypto_make_doc_id(cadmus_u32 value, cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]) {
    if (doc_id == NULL) {
        return;
    }

    doc_id[0] = (cadmus_u8)(value & 0xffu);
    doc_id[1] = (cadmus_u8)((value >> 8) & 0xffu);
    doc_id[2] = (cadmus_u8)((value >> 16) & 0xffu);
    doc_id[3] = (cadmus_u8)((value >> 24) & 0xffu);
}

void crypto_doc_id_to_str(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                          char str[CADMUS_DOC_ID_STR_LEN]) {
    static const char hex[] = "0123456789abcdef";
    cadmus_u32 value;
    int i;

    if (doc_id == NULL || str == NULL) {
        return;
    }

    value = crypto_doc_id_value(doc_id);
    for (i = 7; i >= 0; i--) {
        str[i] = hex[value & 0x0fu];
        value >>= 4;
    }
    str[8] = '\0';
}

CadmusError crypto_doc_id_from_str(const char *str,
                                   cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]) {
    cadmus_u32 value = 0;
    int i;

    if (str == NULL || doc_id == NULL || strlen(str) != 8u) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    for (i = 0; i < 8; i++) {
        int digit = crypto_hex_value(str[i]);
        if (digit < 0) {
            return CADMUS_ERR_INVALID_ARGS;
        }
        value = (value << 4) | (cadmus_u32)digit;
    }

    crypto_make_doc_id(value, doc_id);
    return CADMUS_OK;
}

void crypto_secure_zero(void *buf, cadmus_u32 len) {
    volatile cadmus_u8 *ptr = (volatile cadmus_u8 *)buf;

    if (ptr == NULL) {
        return;
    }

    while (len-- > 0u) {
        *ptr++ = 0;
    }
}

static cadmus_u32 crypto_seed_from_bytes(const cadmus_u8 *data, cadmus_u32 len) {
    cadmus_u32 state = 2166136261u;
    cadmus_u32 i;

    if (data == NULL || len == 0) {
        return state;
    }

    for (i = 0; i < len; i++) {
        state ^= (cadmus_u32)(data[i] + (i * 17u));
        state *= 16777619u;
        state ^= state >> 15;
    }
    return state;
}

static cadmus_u32 crypto_doc_id_value(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]) {
    return (cadmus_u32)doc_id[0] |
           ((cadmus_u32)doc_id[1] << 8) |
           ((cadmus_u32)doc_id[2] << 16) |
           ((cadmus_u32)doc_id[3] << 24);
}

static int crypto_hex_value(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}
