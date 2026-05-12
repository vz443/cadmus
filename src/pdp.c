#include "../include/pdp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static AclEntry *pdp_find_entry(EdocHeader *header, const char *username);
static const AclEntry *pdp_find_entry_const(const EdocHeader *header, const char *username);
static PdpNode *pdp_find_node(PdpNode *node, const char *username);
static PdpNode *pdp_make_node(const char *username, cadmus_u8 permissions);
static void pdp_append_child(PdpNode *parent, PdpNode *child);
static void pdp_permissions_str(cadmus_u8 permissions, char out[5]);

PdpNode *pdp_build_tree(const EdocHeader *header) {
    PdpNode *root;
    PdpNode *nodes[CADMUS_MAX_ACL];
    cadmus_u32 i;

    if (header == NULL) {
        return NULL;
    }

    root = pdp_make_node(header->owner_id, CADMUS_PERM_ALL);
    if (root == NULL) {
        return NULL;
    }

    for (i = 0; i < CADMUS_MAX_ACL; i++) {
        nodes[i] = NULL;
        if (i < header->acl_count && header->acl[i].username[0] != '\0') {
            nodes[i] = pdp_make_node(header->acl[i].username, header->acl[i].permissions);
            if (nodes[i] == NULL) {
                pdp_free_tree(root);
                while (i-- > 0) {
                    free(nodes[i]);
                }
                return NULL;
            }
        }
    }

    for (i = 0; i < CADMUS_MAX_ACL; i++) {
        PdpNode *parent;
        if (nodes[i] == NULL) {
            continue;
        }

        if (header->acl[i].granted_by[0] == '\0' ||
            strcmp(header->acl[i].granted_by, header->owner_id) == 0) {
            parent = root;
        } else {
            parent = pdp_find_node(root, header->acl[i].granted_by);
            if (parent == NULL) {
                cadmus_u32 j;
                parent = NULL;
                for (j = 0; j < CADMUS_MAX_ACL; j++) {
                    if (nodes[j] != NULL && strcmp(nodes[j]->username, header->acl[i].granted_by) == 0) {
                        parent = nodes[j];
                        break;
                    }
                }
                if (parent == nodes[i]) {
                    parent = root;
                }
            }
        }

        if (parent == NULL) {
            parent = root;
        }
        pdp_append_child(parent, nodes[i]);
    }

    return root;
}

void pdp_free_tree(PdpNode *root) {
    if (root == NULL) {
        return;
    }

    pdp_free_tree(root->children);
    pdp_free_tree(root->next);
    free(root);
}

void pdp_print_tree(const PdpNode *node, int depth) {
    char permissions[5];
    int i;

    if (node == NULL) {
        return;
    }

    pdp_permissions_str(node->permissions, permissions);
    for (i = 0; i < depth; i++) {
        printf("  ");
    }
    printf("%s [%s]\n", node->username, permissions);
    pdp_print_tree(node->children, depth + 1);
    pdp_print_tree(node->next, depth);
}

CadmusError pdp_check(const EdocHeader *header, const char *username, cadmus_u8 required_perm) {
    const AclEntry *entry;

    if (header == NULL || username == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    if (strcmp(username, header->owner_id) == 0) {
        return CADMUS_OK;
    }

    entry = pdp_find_entry_const(header, username);
    if (entry == NULL) {
        return CADMUS_ERR_NOT_FOUND;
    }

    if ((entry->permissions & required_perm) != required_perm) {
        return CADMUS_ERR_PERMISSION_DENIED;
    }

    return CADMUS_OK;
}

CadmusError pdp_grant(EdocHeader *header, const char *grantor, const char *grantee, cadmus_u8 permissions) {
    AclEntry *grantor_entry;
    AclEntry *target;
    cadmus_u32 i;
    cadmus_u8 allowed_permissions;

    if (header == NULL || grantor == NULL || grantee == NULL || grantee[0] == '\0' ||
        permissions == 0 || (permissions & ~CADMUS_PERM_ALL) != 0) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    if (strcmp(grantor, header->owner_id) == 0) {
        allowed_permissions = CADMUS_PERM_ALL;
    } else {
        grantor_entry = pdp_find_entry(header, grantor);
        if (grantor_entry == NULL) {
            return CADMUS_ERR_NOT_FOUND;
        }
        if ((grantor_entry->permissions & CADMUS_PERM_SHARE) == 0) {
            return CADMUS_ERR_PERMISSION_DENIED;
        }
        allowed_permissions = grantor_entry->permissions;
    }

    if (strcmp(grantee, header->owner_id) == 0) {
        return CADMUS_OK;
    }

    if ((permissions & allowed_permissions) != permissions) {
        return CADMUS_ERR_PERMISSION_DENIED;
    }

    target = pdp_find_entry(header, grantee);
    if (target == NULL) {
        if (header->acl_count >= CADMUS_MAX_ACL) {
            return CADMUS_ERR_OVERFLOW;
        }
        target = &header->acl[header->acl_count++];
        memset(target, 0, sizeof(*target));
    }

    strncpy(target->username, grantee, CADMUS_USERNAME_MAX - 1);
    strncpy(target->granted_by, grantor, CADMUS_USERNAME_MAX - 1);
    target->permissions = permissions;

    for (i = 0; i < CADMUS_KEY_LEN; i++) {
        target->wrapped_key[i] = 0;
    }

    return CADMUS_OK;
}

CadmusError pdp_revoke(EdocHeader *header, const char *revoker, const char *username) {
    cadmus_u32 i;

    if (header == NULL || revoker == NULL || username == NULL) {
        return CADMUS_ERR_INVALID_ARGS;
    }

    if (strcmp(username, header->owner_id) == 0) {
        return CADMUS_ERR_PERMISSION_DENIED;
    }

    for (i = 0; i < header->acl_count; i++) {
        if (strcmp(header->acl[i].username, username) != 0) {
            continue;
        }

        if (strcmp(revoker, header->owner_id) != 0 &&
            strcmp(revoker, header->acl[i].granted_by) != 0) {
            return CADMUS_ERR_PERMISSION_DENIED;
        }

        for (; i + 1 < header->acl_count; i++) {
            header->acl[i] = header->acl[i + 1];
        }

        if (header->acl_count > 0) {
            header->acl_count--;
            memset(&header->acl[header->acl_count], 0, sizeof(header->acl[header->acl_count]));
        }
        return CADMUS_OK;
    }

    return CADMUS_ERR_NOT_FOUND;
}

const char *pdp_strerror(CadmusError err) {
    switch (err) {
        case CADMUS_OK:
            return "ok";
        case CADMUS_ERR_NOT_FOUND:
            return "not found";
        case CADMUS_ERR_PERMISSION_DENIED:
            return "permission denied";
        case CADMUS_ERR_INVALID_SIGNATURE:
            return "invalid signature";
        case CADMUS_ERR_INVALID_ARGS:
            return "invalid arguments";
        case CADMUS_ERR_OVERFLOW:
            return "too many acl entries";
        default:
            return "policy error";
    }
}

static AclEntry *pdp_find_entry(EdocHeader *header, const char *username) {
    cadmus_u32 i;

    if (header == NULL || username == NULL) {
        return NULL;
    }

    for (i = 0; i < header->acl_count && i < CADMUS_MAX_ACL; i++) {
        if (strcmp(header->acl[i].username, username) == 0) {
            return &header->acl[i];
        }
    }

    return NULL;
}

static const AclEntry *pdp_find_entry_const(const EdocHeader *header, const char *username) {
    cadmus_u32 i;

    if (header == NULL || username == NULL) {
        return NULL;
    }

    for (i = 0; i < header->acl_count && i < CADMUS_MAX_ACL; i++) {
        if (strcmp(header->acl[i].username, username) == 0) {
            return &header->acl[i];
        }
    }

    return NULL;
}

static PdpNode *pdp_find_node(PdpNode *node, const char *username) {
    PdpNode *found;

    if (node == NULL || username == NULL) {
        return NULL;
    }

    if (strcmp(node->username, username) == 0) {
        return node;
    }

    found = pdp_find_node(node->children, username);
    if (found != NULL) {
        return found;
    }

    return pdp_find_node(node->next, username);
}

static PdpNode *pdp_make_node(const char *username, cadmus_u8 permissions) {
    PdpNode *node = (PdpNode *)calloc(1, sizeof(PdpNode));
    if (node == NULL) {
        return NULL;
    }

    strncpy(node->username, username, CADMUS_USERNAME_MAX - 1);
    node->permissions = permissions;
    return node;
}

static void pdp_append_child(PdpNode *parent, PdpNode *child) {
    if (parent == NULL || child == NULL) {
        return;
    }

    child->next = parent->children;
    parent->children = child;
}

static void pdp_permissions_str(cadmus_u8 permissions, char out[5]) {
    out[0] = (permissions & CADMUS_PERM_READ) ? 'r' : '-';
    out[1] = (permissions & CADMUS_PERM_WRITE) ? 'w' : '-';
    out[2] = (permissions & CADMUS_PERM_SHARE) ? 's' : '-';
    out[3] = (permissions & CADMUS_PERM_DELETE) ? 'd' : '-';
    out[4] = '\0';
}
