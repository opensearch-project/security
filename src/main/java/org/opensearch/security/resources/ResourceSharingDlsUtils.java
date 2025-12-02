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
import java.util.List;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.privileges.dlsfls.DlsRestriction;
import org.opensearch.security.privileges.dlsfls.DocumentPrivileges;
import org.opensearch.security.privileges.dlsfls.IndexToRuleMap;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.user.User;

public class ResourceSharingDlsUtils {
    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingDlsUtils.class);

    public static IndexToRuleMap<DlsRestriction> resourceRestrictions(
        NamedXContentRegistry xContentRegistry,
        IndexResolverReplacer.Resolved resolved,
        User user
    ) {

        List<String> principals = new ArrayList<>();
        principals.add("user:*"); // Convention for publicly visible
        principals.add("user:" + user.getName()); // owner

        // Security roles (OpenSearch Security roles)
        if (user.getSecurityRoles() != null) {
            user.getSecurityRoles().forEach(r -> principals.add("role:" + r));
        }

        // Backend roles (LDAP/SAML/etc)
        if (user.getRoles() != null) {
            user.getRoles().forEach(br -> principals.add("backend:" + br));
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
        for (String index : resolved.getAllIndices()) {
            mapBuilder.put(index, restriction);
        }
        return new IndexToRuleMap<>(mapBuilder.build());
    }
}
