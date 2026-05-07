#ifndef CADMUS_PDP_H
#define CADMUS_PDP_H

/*
 * Policy Decision Point.
 * Enforces ACL permissions stored in an EdocHeader.
 * Owner implicitly holds CADMUS_PERM_ALL and is never denied.
 * Assigned to: Varen
 */

#include "types.h"
#include "edoc.h"

/*
 * ACL visualisation tree.
 * Root = owner. Children = users granted access by their parent node.
 */
typedef struct PdpNode {
    char            username[CADMUS_USERNAME_MAX];
    cadmus_u8       permissions;
    cadmus_u32      expires;
    struct PdpNode *children;
    struct PdpNode *next;
} PdpNode;

/* Varen returns heap-allocated tree; free with pdp_free_tree() */
PdpNode *pdp_build_tree(const EdocHeader *header);

/* Varen */
void pdp_free_tree(PdpNode *root);

/* Varen pretty-prints the tree; call with depth=0 */
void pdp_print_tree(const PdpNode *node, int depth);

/*
 * Check whether username holds all bits in required_perm.
 * Returns CADMUS_OK, CADMUS_ERR_PERMISSION_DENIED,
 *         CADMUS_ERR_EXPIRED, or CADMUS_ERR_NOT_FOUND.
 */
/* Varen */
CadmusError pdp_check(const EdocHeader *header,
                       const char *username,
                       cadmus_u8 required_perm);

/*
 * Add or update an ACL entry. Grantor must hold CADMUS_PERM_SHARE
 * and cannot escalate beyond their own permissions.
 * Caller must re-sign and persist the header afterwards.
 */
/* Varen */
CadmusError pdp_grant(EdocHeader *header,
                       const char *grantor,
                       const char *grantee,
                       cadmus_u8 permissions,
                       cadmus_u32 expires);

/*
 * Remove a user's ACL entry.
 * Only the owner or the original grantor may revoke.
 */
/* Varen */
CadmusError pdp_revoke(EdocHeader *header,
                        const char *revoker,
                        const char *username);

/* Varen returns a static human-readable string for an error code */
const char *pdp_strerror(CadmusError err);

#endif /* CADMUS_PDP_H */
