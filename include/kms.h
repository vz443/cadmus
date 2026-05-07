#ifndef CADMUS_KMS_H
#define CADMUS_KMS_H

/*
 * Key Management System.
 * Derives keys from passwords and manages the session file.
 *
 * Session file: $HOME/.cadmus/session-key  (permissions: 0600)
 * Contents: [CADMUS_USERNAME_MAX bytes username][CADMUS_KEY_LEN bytes key]
 *
 * Assigned to: Thrishaan
 */

#include "types.h"

/* Thrishaan SHA-256(password) -> key_out */
void kms_derive_key(const char *password,
                    cadmus_u8 key_out[CADMUS_KEY_LEN]);

/* Thrishaan write session file, set permissions to 0600 */
CadmusError kms_store_session(const char *username,
                               const cadmus_u8 key[CADMUS_KEY_LEN]);

/* Thrishaan read session file; either out param may be NULL */
CadmusError kms_load_session(char username_out[CADMUS_USERNAME_MAX],
                              cadmus_u8 key_out[CADMUS_KEY_LEN]);

/* Thrishaan zero then delete the session file */
CadmusError kms_clear_session(void);

/* Thrishaan build $HOME/.cadmus/ path into buf */
CadmusError kms_cadmus_dir(char *buf, int buf_size);

/* Thrishaan build $HOME/.cadmus/session-key path into buf */
CadmusError kms_session_path(char *buf, int buf_size);

/* Thrishaan build $HOME/.cadmus/store/ path into buf */
CadmusError kms_store_path(char *buf, int buf_size);

/* Thrishaan build $HOME/.cadmus/users path into buf */
CadmusError kms_users_path(char *buf, int buf_size);

/* Thrishaan create .cadmus/ and .cadmus/store/ if they don't exist */
CadmusError kms_init_dirs(void);

#endif /* CADMUS_KMS_H */
