#include "../include/compression.h"
#include <stdlib.h>

CadmusError compression_rle_compress(const cadmus_u8 *in, cadmus_u32 in_len, cadmus_u8 **out, cadmus_u32 *out_len) {
    cadmus_u8 *buf;
    cadmus_u32 i;
    cadmus_u32 j = 0;

    if (out == NULL || out_len == NULL || (in == NULL && in_len != 0)) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    *out = NULL;
    *out_len = 0;

    if (in_len == 0) {
        return CADMUS_OK;
    }

    if (in_len > 0xffffffffu / 2u) {
        return CADMUS_ERR_OVERFLOW;
    }

    buf = (cadmus_u8 *)malloc((size_t)in_len * 2u);
    if (buf == NULL) {
        return CADMUS_ERR_ALLOC;
    }

    i = 0;
    while (i < in_len) {
        cadmus_u8 count = 1;
        while (i + count < in_len && count < 255 && in[i + count] == in[i]) {
            count++;
        }
        buf[j++] = count;
        buf[j++] = in[i];
        i += count;
    }

    *out = buf;
    *out_len = j;
    return CADMUS_OK;
}

CadmusError compression_rle_decompress(const cadmus_u8 *in, cadmus_u32 in_len, cadmus_u32 expected_len, cadmus_u8 **out, cadmus_u32 *out_len) {
    cadmus_u8 *buf;
    cadmus_u32 i;
    cadmus_u32 j = 0;
    cadmus_u32 k;

    if (out == NULL || out_len == NULL || (in == NULL && in_len != 0)) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    *out = NULL;
    *out_len = 0;

    if (expected_len == 0) {
        if (in_len == 0) {
            return CADMUS_OK;
        }
        return CADMUS_ERR_TAMPERED;
    }

    if ((in_len & 1u) != 0u) {
        return CADMUS_ERR_TAMPERED;
    }

    buf = (cadmus_u8 *)malloc(expected_len);
    if (buf == NULL) {
        return CADMUS_ERR_ALLOC;
    }

    for (i = 0; i < in_len; i += 2) {
        cadmus_u8 count = in[i];
        cadmus_u8 value = in[i + 1];

        if (count == 0 || j + count > expected_len) {
            free(buf);
            return CADMUS_ERR_TAMPERED;
        }

        for (k = 0; k < count; k++) {
            buf[j++] = value;
        }
    }

    if (j != expected_len) {
        free(buf);
        return CADMUS_ERR_TAMPERED;
    }

    *out = buf;
    *out_len = expected_len;
    return CADMUS_OK;
}
