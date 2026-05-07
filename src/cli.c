#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/cli.h"


void file_upload(const char *filepath, int delete_original) {}
void file_read(const char *doc_id) {}
void file_share(const char *doc_id, const char *username,
                const char *permission, const char *expires) {}

void print_usage(void) {
    printf("\nUsage:\n");
    printf("  cadmus auth login <username>\n");
    printf("  cadmus auth logout\n");
    printf("  cadmus auth register <username>\n");
    printf("  cadmus file upload <filepath> [-d]\n");
    printf("  cadmus file read <doc_id>\n");
    printf("  cadmus file share <doc_id> <username> --permission <perm> [--expires <date>]\n\n");
}

void handle_auth(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Error: missing auth subcommand (login, logout, register)\n");
        print_usage();
        return;
    }

    const char *subcommand = argv[2];

    if (strcmp(subcommand, "login") == 0) {
        if (argc < 4) {
            printf("Error: login requires a username. e.g. cadmus auth login dave\n");
            return;
        }
        cmd_auth_login(argv[3]);

    } else if (strcmp(subcommand, "logout") == 0) {
        cmd_auth_logout();

    } else if (strcmp(subcommand, "register") == 0) {
        if (argc < 4) {
            printf("Error: register requires a username. e.g. cadmus auth register dave\n");
            return;
        }
        cmd_auth_register(argv[3]);

    } else {
        printf("Error: unknown auth command '%s'\n", subcommand);
        print_usage();
    }
}

void handle_file(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Error: missing file subcommand (upload, read, share)\n");
        print_usage();
        return;
    }

    const char *subcommand = argv[2];

    if (strcmp(subcommand, "upload") == 0) {
        if (argc < 4) {
            printf("Error: upload requires a filepath. e.g. cadmus file upload myfile.pdf\n");
            return;
        }
        const char *filepath = argv[3];
        int delete_original = 0;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0) {
                delete_original = 1;
            }
        }
        file_upload(filepath, delete_original);

    } else if (strcmp(subcommand, "read") == 0) {
        if (argc < 4) {
            printf("Error: read requires a doc_id. e.g. cadmus file read abc-123\n");
            return;
        }
        file_read(argv[3]);

    } else if (strcmp(subcommand, "share") == 0) {
        if (argc < 6) {
            printf("Error: share requires doc_id, username and --permission.\n");
            printf("  e.g. cadmus file share abc-123 dave --permission read\n");
            return;
        }

        const char *doc_id     = argv[3];
        const char *username   = argv[4];
        const char *permission = NULL;
        const char *expires    = NULL;

        for (int i = 5; i < argc; i++) {
            if (strcmp(argv[i], "--permission") == 0 && i + 1 < argc) {
                permission = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "--expires") == 0 && i + 1 < argc) {
                expires = argv[i + 1];
                i++;
            }
        }

        if (permission == NULL) {
            printf("Error: --permission is required (read, write, share, delete)\n");
            return;
        }

        file_share(doc_id, username, permission, expires);

    } else {
        printf("Error: unknown file command '%s'\n", subcommand);
        print_usage();
    }
}

void parse_and_route(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Error: no command provided.\n");
        print_usage();
        return;
    }

    const char *category = argv[1];

    if (strcmp(category, "auth") == 0) {
        handle_auth(argc, argv);
    } else if (strcmp(category, "file") == 0) {
        handle_file(argc, argv);
    } else {
        printf("Error: unknown command '%s'\n", category);
        print_usage();
    }
}

int main(int argc, char *argv[]) {
    parse_and_route(argc, argv);
    return 0;
}
