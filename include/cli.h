#ifndef CADMUS_CLI_H
#define CADMUS_CLI_H

/*
 * CLI parser and command dispatcher.
 *
 * Usage: cadmus <group> <subcommand> [args] [flags]
 *
 * Groups:  auth  (register, login, logout)
 *          file  (upload, read, share, list, delete)
 *
 * Flags:   -d                     delete original after upload
 *          --permission <perms>   comma-separated: read,write,share,delete
 *          --expires <value>      unix timestamp or YYYY-MM-DD
 *          -v / --verbose         enable debug logging
 *          -h / --help            show help
 *
 * Assigned to: Zakariya
 */

#include "types.h"

/* Zakariya */
CadmusError cli_dispatch(int argc, char *argv[]);

/* Zakariya */
void cli_help(void);
void cli_help_auth(void);
void cli_help_file(void);

/* auth commands */

/* Zakariya */
CadmusError cmd_auth_register(int argc, char *argv[]);

/* Zakariya */
CadmusError cmd_auth_login(int argc, char *argv[]);

/* Zakariya */
CadmusError cmd_auth_logout(int argc, char *argv[]);

/* file commands */

/* Zakariya */
CadmusError cmd_file_upload(int argc, char *argv[]);

/* Zakariya */
CadmusError cmd_file_read(int argc, char *argv[]);

/* Zakariya */
CadmusError cmd_file_share(int argc, char *argv[]);

/* Zakariya */
CadmusError cmd_file_list(int argc, char *argv[]);

/* Zakariya */
CadmusError cmd_file_delete(int argc, char *argv[]);

/* Helpers */

/* Zakariya parse "read,write" -> CADMUS_PERM_* bitmask */
CadmusError cli_parse_permissions(const char *str, cadmus_u8 *perm_out);

/* Zakariya parse unix timestamp or YYYY-MM-DD */
CadmusError cli_parse_expires(const char *str, cadmus_u32 *expires_out);

/* Zakariya read password from terminal without echoing */
void cli_read_password(const char *prompt, char *buf, int buf_len);

/* Zakariya print a human-readable error message to stderr */
void cli_print_error(CadmusError err, const char *context);

#endif /* CADMUS_CLI_H */
