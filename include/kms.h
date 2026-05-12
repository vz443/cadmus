#ifndef CADMUS_KMS_H
#define CADMUS_KMS_H

/*
 * Key derivation and flat-file paths in the current working directory.
 *
 * Session file: cadmus_session.bin
 * Users file:   cadmus_users.txt
 * Index file:   cadmus_index.txt
 */

#include "types.h"

/* Derive a fixed-length key from a password string. */
void kms_derive_key(const char *password,
                    cadmus_u8 key_out[CADMUS_KEY_LEN]);

/* Write the session file for the current user. */
CadmusError kms_store_session(const char *username,
                               const cadmus_u8 key[CADMUS_KEY_LEN]);

/* Read the session file; either output parameter may be NULL. */
CadmusError kms_load_session(char username_out[CADMUS_USERNAME_MAX],
                              cadmus_u8 key_out[CADMUS_KEY_LEN]);

/* Clear the active session file. */
CadmusError kms_clear_session(void);

/* Build the current working directory marker into buf. */
CadmusError kms_cadmus_dir(char *buf, int buf_size);

/* Build the session file path into buf. */
CadmusError kms_session_path(char *buf, int buf_size);

/* Build the document file prefix into buf. */
CadmusError kms_store_path(char *buf, int buf_size);

/* Build the users file path into buf. */
CadmusError kms_users_path(char *buf, int buf_size);

/* Build the index file path into buf. */
CadmusError kms_index_path(char *buf, int buf_size);

/* Compatibility helper for the flat-file design. */
CadmusError kms_init_dirs(void);

#endif /* CADMUS_KMS_H */
