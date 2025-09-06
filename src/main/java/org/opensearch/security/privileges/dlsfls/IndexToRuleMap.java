/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.privileges.dlsfls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.user.User;

/**
 * Maps index names to DLS/FLS/FM rules.
 * <p>
 * This only contains index names, not any alias or data stream names.
 * <p>
 * This map should be only used when really necessary, as computing a whole map of indices can be expensive.
 * It should be preferred to directly query the privilege status of indices using the getRestriction() methods
 * of the sub-classes of AbstractRuleBasedPrivileges.
 */
public class IndexToRuleMap<Rule extends AbstractRuleBasedPrivileges.Rule> {
    private static final Logger LOGGER = LogManager.getLogger(IndexToRuleMap.class);
    private static final IndexToRuleMap<?> UNRESTRICTED = new IndexToRuleMap<AbstractRuleBasedPrivileges.Rule>(ImmutableMap.of());

    private final ImmutableMap<String, Rule> indexMap;

    IndexToRuleMap(ImmutableMap<String, Rule> indexMap) {
        this.indexMap = indexMap;
    }

    public boolean isUnrestricted() {
        return this.indexMap.isEmpty() || this.indexMap.values().stream().allMatch(Rule::isUnrestricted);
    }

    public ImmutableMap<String, Rule> getIndexMap() {
        return indexMap;
    }

    public boolean containsAny(Predicate<Rule> predicate) {
        if (indexMap.isEmpty()) {
            return false;
        }

        for (Rule rule : this.indexMap.values()) {
            if (predicate.test(rule)) {
                return true;
            }
        }

        return false;
    }

    @SuppressWarnings("unchecked")
    public static <Rule extends AbstractRuleBasedPrivileges.Rule> IndexToRuleMap<Rule> unrestricted() {
        return (IndexToRuleMap<Rule>) UNRESTRICTED;
    }

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
            builder.startObject().startObject("terms").array("all_shared_principals.keyword", principals.toArray()).endObject().endObject();

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
