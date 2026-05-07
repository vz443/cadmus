#ifndef CADMUS_AUTH_H
#define CADMUS_AUTH_H

/*
 * User authentication and registry.
 *
 * Registry file: $HOME/.cadmus/users
 * Format: one line per user -> "username:sha256hex\n"
 *
 * Assigned to: Le Vinh
 */

#include "types.h"

/* Le Vinh */
CadmusError auth_register(const char *username, const char *password);

/* Le Vinh */
CadmusError auth_login(const char *username, const char *password);

/* Le Vinh */
CadmusError auth_logout(void);

/* Le Vinh writes current username into out (CADMUS_USERNAME_MAX bytes) */
CadmusError auth_whoami(char out[CADMUS_USERNAME_MAX]);

/* Le Vinh returns 1 if user exists, 0 otherwise */
int auth_user_exists(const char *username);

#endif /* CADMUS_AUTH_H */
