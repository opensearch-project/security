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
        User user,
        ResourcePluginInfo resourcePluginInfo
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

        // Workspace visibility is expressed as a separate clause on the resource's own `workspaces` field (which OSD
        // maintains), rather than by denormalizing workspace:<id> into all_shared_principals. Membership comes from
        // ResourceSharingExtension.resolveWorkspacesForUser, whose SPI contract requires a trusted, server-set,
        // I/O-free source (see that interface's javadoc). Filtering the live field means associate/dissociate are
        // reflected automatically. If no extension implements the resolver, the set is empty and the clause is omitted.
        Set<String> userWorkspaces = resourcePluginInfo == null ? Set.of() : resourcePluginInfo.resolveWorkspacesForUser(user);

        // The workspaces clause targets the field each provider actually declares (workspacesField()), resolved per
        // index — not a hardcoded name — so it matches the field ingestion reads. Built per index accordingly.
        ImmutableMap.Builder<String, DlsRestriction> mapBuilder = ImmutableMap.builder();
        for (String index : resolvedIndices) {
            String workspacesField = resourcePluginInfo == null ? null : resourcePluginInfo.workspacesFieldForIndex(index);
            mapBuilder.put(index, buildRestriction(xContentRegistry, principals, workspacesField, userWorkspaces));
        }
        return new IndexToRuleMap<>(mapBuilder.build());
    }

    /**
     * Builds the per-index DLS restriction: a doc is visible if it is shared with one of the user's principals OR (when
     * the index declares a workspaces field and the user has workspace access) it belongs to one of the user's
     * workspaces — {@code bool.should[ terms(all_shared_principals), terms(<workspacesField>) ]}, min_should_match=1.
     */
    private static DlsRestriction buildRestriction(
        NamedXContentRegistry xContentRegistry,
        List<String> principals,
        String workspacesField,
        Set<String> userWorkspaces
    ) {
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.startObject().startObject("bool").startArray("should");
            builder.startObject().startObject("terms").array("all_shared_principals", principals.toArray()).endObject().endObject();
            if (workspacesField != null && !userWorkspaces.isEmpty()) {
                builder.startObject().startObject("terms").array(workspacesField, userWorkspaces.toArray()).endObject().endObject();
            }
            builder.endArray().field("minimum_should_match", 1).endObject().endObject();

            return new DlsRestriction(List.of(DocumentPrivileges.getRenderedDlsQuery(xContentRegistry, builder.toString())));
        } catch (IOException e) {
            LOGGER.warn("Received error while applying resource restrictions.", e);
            return DlsRestriction.FULL;
        }
    }

}
