#ifndef CADMUS_CRYPTO_H
#define CADMUS_CRYPTO_H

/* Simple educational encryption and checksum helpers. */

#include "types.h"

/* Mix arbitrary bytes into a fixed-length key buffer. */
void crypto_mix_bytes(const cadmus_u8 *seed,
                      cadmus_u32 seed_len,
                      cadmus_u8 key_out[CADMUS_KEY_LEN]);

/* Derive a document key from a session key and document id. */
void crypto_derive_doc_key(const cadmus_u8 session_key[CADMUS_KEY_LEN],
                           const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                           cadmus_u8 doc_key_out[CADMUS_KEY_LEN]);

/* Encrypt or decrypt bytes with a simple XOR stream. */
void crypto_xor_stream(const cadmus_u8 key[CADMUS_KEY_LEN],
                       const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                       const cadmus_u8 *in,
                       cadmus_u8 *out,
                       cadmus_u32 len);

/* Compute a simple rolling checksum. */
cadmus_u32 crypto_checksum32(const cadmus_u8 *data, cadmus_u32 len);

/* Compute a key-dependent checksum. */
cadmus_u32 crypto_keyed_checksum32(const cadmus_u8 key[CADMUS_KEY_LEN],
                                   const cadmus_u8 *data,
                                   cadmus_u32 len);

/* Build a binary document id from a sequential number. */
void crypto_make_doc_id(cadmus_u32 value, cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]);

/* Convert a binary document id to an 8-digit hex string. */
void crypto_doc_id_to_str(const cadmus_u8 doc_id[CADMUS_DOC_ID_LEN],
                          char str[CADMUS_DOC_ID_STR_LEN]);

/* Parse an 8-digit hex string into a binary document id. */
CadmusError crypto_doc_id_from_str(const char *str,
                                   cadmus_u8 doc_id[CADMUS_DOC_ID_LEN]);

/* Zero sensitive memory in a way that resists optimization. */
void crypto_secure_zero(void *buf, cadmus_u32 len);

#endif /* CADMUS_CRYPTO_H */
