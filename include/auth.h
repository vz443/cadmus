#ifndef CADMUS_AUTH_H
#define CADMUS_AUTH_H

/*
 * User authentication and registry.
 *
 * Registry file: cadmus_users.txt
 * Format: one line per user -> "username:passwordhash\n"
 */

#include "types.h"

/* Register a new user in the local credential registry. */
CadmusError auth_register(const char *username, const char *password);

/* Verify credentials and create a local session. */
CadmusError auth_login(const char *username, const char *password);

/* Clear the active local session. */
CadmusError auth_logout(void);

/* Write the current username into out (CADMUS_USERNAME_MAX bytes). */
CadmusError auth_whoami(char out[CADMUS_USERNAME_MAX]);

/* Return 1 if the user exists, 0 otherwise. */
int auth_user_exists(const char *username);

#endif /* CADMUS_AUTH_H */
