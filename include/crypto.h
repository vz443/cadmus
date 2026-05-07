#ifndef CADMUS_CRYPTO_H
#define CADMUS_CRYPTO_H

/* Assigned to: Varen */

#include "types.h"

typedef struct {
    cadmus_u32 state[8];
    cadmus_u8  buf[64];
    cadmus_u32 bits_lo;
    cadmus_u32 bits_hi;
    cadmus_u32 buf_len;
} Sha256Ctx;

/* Varen */
void chacha20_block(const cadmus_u8 key[CADMUS_KEY_LEN],
                    const cadmus_u8 nonce[CADMUS_NONCE_LEN],
                    cadmus_u32 counter,
                    cadmus_u8 out[64]);

/* Varen */
void chacha20_xor(const cadmus_u8 *key,
                  const cadmus_u8 *nonce,
                  cadmus_u32 counter,
                  const cadmus_u8 *in,
                  cadmus_u8 *out,
                  cadmus_u32 len);

/* Varen */
void sha256_init(Sha256Ctx *ctx);

/* Varen */
void sha256_update(Sha256Ctx *ctx, const cadmus_u8 *data, cadmus_u32 len);

/* Varen */
void sha256_final(Sha256Ctx *ctx, cadmus_u8 hash[CADMUS_SHA256_LEN]);

/* Varen */
void sha256(const cadmus_u8 *data, cadmus_u32 len,
            cadmus_u8 hash[CADMUS_SHA256_LEN]);

/* Varen */
void hmac_sha256(const cadmus_u8 *key, cadmus_u32 key_len,
                 const cadmus_u8 *msg, cadmus_u32 msg_len,
                 cadmus_u8 mac_out[CADMUS_HMAC_LEN]);

/* Varen returns 1 if valid, 0 if not */
int hmac_sha256_verify(const cadmus_u8 *key, cadmus_u32 key_len,
                       const cadmus_u8 *msg, cadmus_u32 msg_len,
                       const cadmus_u8 expected[CADMUS_HMAC_LEN]);

/* Varen */
void crypto_gen_nonce(cadmus_u8 nonce[CADMUS_NONCE_LEN]);

/* Varen */
void crypto_gen_uuid(cadmus_u8 uuid[CADMUS_DOC_ID_LEN]);

/* Varen */
void crypto_uuid_to_str(const cadmus_u8 uuid[CADMUS_DOC_ID_LEN],
                        char str[CADMUS_DOC_ID_STR_LEN]);

/* Varen */
void crypto_secure_zero(void *buf, cadmus_u32 len);

#endif /* CADMUS_CRYPTO_H */
