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
 *          -v / --verbose         enable debug logging
 *          -h / --help            show help
 *
 */

#include "types.h"

CadmusError cli_dispatch(int argc, char *argv[]);

void cli_help(void);
void cli_help_auth(void);
void cli_help_file(void);

CadmusError cmd_auth_register(int argc, char *argv[]);

CadmusError cmd_auth_login(int argc, char *argv[]);

CadmusError cmd_auth_logout(int argc, char *argv[]);

CadmusError cmd_file_upload(int argc, char *argv[]);

CadmusError cmd_file_read(int argc, char *argv[]);

CadmusError cmd_file_share(int argc, char *argv[]);

CadmusError cmd_file_list(int argc, char *argv[]);

CadmusError cmd_file_delete(int argc, char *argv[]);

CadmusError cli_parse_permissions(const char *str, cadmus_u8 *perm_out);

void cli_read_password(const char *prompt, char *buf, int buf_len);

void cli_print_error(CadmusError err, const char *context);

#endif /* CADMUS_CLI_H */
