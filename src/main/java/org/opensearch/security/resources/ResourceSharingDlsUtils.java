/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.DocumentPrivileges;
import org.opensearch.security.privileges.dlsfls.IndexToRuleMap;
import org.opensearch.security.user.User;

public class ResourceSharingDlsUtils {
    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingDlsUtils.class);

    public static IndexToRuleMap<DlsRestriction> resourceRestrictions(
        NamedXContentRegistry xContentRegistry,
        Collection<String> resolvedIndices,
        User user
    ) {

        List<String> principals = new ArrayList<>();
        principals.add("public"); // matches resources shared via general_access
        principals.add("user:" + user.getName()); // owner

        // Security roles (OpenSearch Security roles)
        if (user.getSecurityRoles() != null) {
            user.getSecurityRoles().forEach(r -> principals.add("role:" + r));
        }

        // Backend roles (LDAP/SAML/etc)
        if (user.getRoles() != null) {
            user.getRoles().forEach(br -> principals.add("backend:" + br));
        }

        // Workspace principals: the workspaces this user can access, added as workspace:<id> so they
        // intersect the workspace:<id> principals denormalized onto resources that belong to those
        // workspaces (see ResourceSharing#getAllPrincipals). This keeps the read path I/O-free — required
        // for the privilege hot path.
        //
        // SECURITY: workspace membership is an authorization input, so it MUST originate from a trusted,
        // server-set source and MUST NOT be assertable by the requesting user (e.g. via JWT/proxy claims).
        // The trusted resolution mechanism is not yet defined (see design doc), so this is DISABLED by
        // default: resolveUserWorkspaces returns empty until a server-set source is wired behind an
        // explicit trust boundary. This prevents a privilege-escalation vector where a user could claim
        // arbitrary workspace membership and read those workspaces' resources.
        for (String workspaceId : resolveUserWorkspaces(user)) {
            principals.add("workspace:" + workspaceId);
        }

        XContentBuilder builder = null;
        DlsRestriction restriction;
        try {
            // Build a single `terms` query JSON
            builder = XContentFactory.jsonBuilder();
            builder.startObject().startObject("terms").array("all_shared_principals", principals.toArray()).endObject().endObject();

            String dlsJson = builder.toString();
            restriction = new DlsRestriction(List.of(DocumentPrivileges.getRenderedDlsQuery(xContentRegistry, dlsJson)));
        } catch (IOException e) {
            LOGGER.warn("Received error while applying resource restrictions.", e);
            restriction = DlsRestriction.FULL;
        }

        ImmutableMap.Builder<String, DlsRestriction> mapBuilder = ImmutableMap.builder();
        for (String index : resolvedIndices) {
            mapBuilder.put(index, restriction);
        }
        return new IndexToRuleMap<>(mapBuilder.build());
    }

    /**
     * Resolves the set of workspace IDs the given user can access, without any I/O (required on the privilege
     * hot path).
     *
     * <p><b>Intentionally disabled in this spike.</b> Because the result feeds authorization (via the
     * {@code workspace:<id>} DLS principals), the workspace list MUST come from a trusted, server-set source
     * that the requesting user cannot assert. That trusted mechanism (how workspace membership is resolved and
     * safely attached to the {@link User} at authentication time) is not yet defined — see the design doc — so
     * this returns an empty set rather than trusting a potentially user-influenced custom attribute. Wiring a
     * server-set source behind an explicit trust boundary is a hard prerequisite before enabling this.
     *
     * @param user the authenticated user
     * @return the set of trusted workspace IDs the user belongs to; empty until a server-set source is wired
     */
    private static Set<String> resolveUserWorkspaces(User user) {
        // No trusted server-set source of workspace membership exists yet; do not derive it from user-assertable
        // attributes. Returning empty keeps read-path behavior safe (no workspace-based visibility) until the
        // trusted resolution is implemented.
        return Collections.emptySet();
    }
}
