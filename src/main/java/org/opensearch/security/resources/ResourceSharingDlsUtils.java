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
import java.util.HashSet;
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
        // for the privilege hot path — by resolving the user's workspaces from in-memory User attributes
        // rather than querying the sharing index here.
        // SPIKE NOTE: the attribute key and the mechanism that populates it (workspace membership -> user
        // attribute at authc time) are not yet defined. This reads a placeholder custom attribute so the
        // end-to-end intersection can be exercised in tests; production wiring is an open item (see design doc).
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
     * Resolves the set of workspace IDs the given user can access, without any I/O (required on the
     * privilege hot path). Reads a comma-separated custom attribute off the in-memory {@link User}.
     *
     * <p>SPIKE: {@code WORKSPACES_ATTRIBUTE} and the authc-time mechanism that populates it are placeholders
     * to make the DLS intersection testable end-to-end. Production design (where workspace membership is
     * resolved and how it lands on the User) is an open question tracked in the design doc.
     *
     * @param user the authenticated user
     * @return the set of workspace IDs, or an empty set if none are present
     */
    private static Set<String> resolveUserWorkspaces(User user) {
        String raw = user.getCustomAttributesMap() == null ? null : user.getCustomAttributesMap().get(WORKSPACES_ATTRIBUTE);
        if (raw == null || raw.isBlank()) {
            return Collections.emptySet();
        }
        Set<String> workspaces = new HashSet<>();
        for (String id : raw.split(",")) {
            String trimmed = id.trim();
            if (!trimmed.isEmpty()) {
                workspaces.add(trimmed);
            }
        }
        return workspaces;
    }

    /** SPIKE placeholder custom-attribute key carrying the user's accessible workspace IDs. */
    private static final String WORKSPACES_ATTRIBUTE = "attr.internal.workspaces";
}
