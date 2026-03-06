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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.CheckedFunction;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.privileges.CompiledRoles;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.security.util.MockIndexMetadataBuilder;

import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * Performance test for {@link DocumentPrivileges} and {@link AbstractRuleBasedPrivileges.StatefulRules} construction.
 * <p>
 * Mirrors {@code RoleBasedActionPrivilegesTest.ClusterPrivileges.constructionPerformance_sharedPatterns} for the
 * DLS layer, verifying that {@link CompiledRoles} + {@link AbstractRuleBasedPrivileges.StatefulRules} using
 * {@code IndexPattern.matchingNonDynamic(SortedMap)} is efficient at scale.
 */
public class DocumentPrivilegesConstructionPerformanceTest {
    static NamedXContentRegistry xContentRegistry = new NamedXContentRegistry(
        ImmutableList.of(
            new NamedXContentRegistry.Entry(
                QueryBuilder.class,
                new ParseField(TermQueryBuilder.NAME),
                (CheckedFunction<XContentParser, TermQueryBuilder, IOException>) (p) -> TermQueryBuilder.fromXContent(p)
            )
        )
    );

    /**
     * Tests StatefulRules construction performance for DocumentPrivileges.
     * <p>
     * Simulates:
     * <ul>
     *   <li>3000 roles, each with a unique prefix pattern "role_N*" (matching ~3 indices) plus a shared "test-index"</li>
     *   <li>6000 indices + 9000 aliases</li>
     *   <li>DLS query with user-attribute substitution (${attr.internal.should_hide})</li>
     * </ul>
     * The test runs 100 iterations and prints timing per iteration so that regressions are visible.
     */
    @Test
    public void constructionPerformance_sharedPatterns() throws Exception {
        final int NUM_ROLES = 3000;
        final int NUM_INDICES = 6000;
        final int NUM_ALIASES = 9000;
        final int INDICES_PER_ROLE = 3;

        // DLS query with user attribute substitution
        String dlsQuery = "{\"term\": {\"should_hide\": \"${attr.internal.should_hide}\"}}";

        // Build roles: each has pattern "role_N*" + shared "test-index"
        Map<String, Object> rolesMap = new HashMap<>();
        for (int i = 0; i < NUM_ROLES; i++) {
            List<String> indexPatterns = Arrays.asList("role_" + i + "*", "test-index");

            Map<String, Object> indexPermission = new HashMap<>();
            indexPermission.put("index_patterns", indexPatterns);
            indexPermission.put("dls", dlsQuery);
            indexPermission.put("allowed_actions", Arrays.asList("indices:data/read/*"));

            rolesMap.put("role_" + i + "_user", ImmutableMap.of("index_permissions", Arrays.asList(indexPermission)));
        }
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromMap(rolesMap, CType.ROLES);

        // Build indices: INDICES_PER_ROLE indices per role matching "role_N*"
        String[] suffixes = { "_data", "_logs", "_metrics" };
        MockIndexMetadataBuilder builder = indices();
        for (int i = 0; i < NUM_ROLES; i++) {
            for (int j = 0; j < INDICES_PER_ROLE; j++) {
                builder.index("role_" + i + suffixes[j % suffixes.length]);
            }
        }
        builder.index("test-index");
        // Fill remaining indices to reach NUM_INDICES
        int createdIndices = NUM_ROLES * INDICES_PER_ROLE + 1;
        for (int i = createdIndices; i < NUM_INDICES; i++) {
            builder.index("other_index_" + i);
        }
        // Aliases each pointing to one role's first index
        for (int i = 0; i < NUM_ALIASES; i++) {
            builder.alias("alias_" + i).of("role_" + (i % NUM_ROLES) + suffixes[0]);
        }
        Metadata indexMetadata = builder.build();
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(indexMetadata).build();

        // Load static action groups
        JsonNode staticActionGroupsJsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(
            DynamicConfigFactory.class.getResourceAsStream("/static_config/static_action_groups.yml")
        );
        SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfig = SecurityDynamicConfiguration.fromNode(
            staticActionGroupsJsonNode,
            CType.ACTIONGROUPS,
            2,
            0,
            0
        );
        FlattenedActionGroups actionGroups = new FlattenedActionGroups(actionGroupsConfig);

        SortedMap<String, IndexAbstraction> indicesLookup = indexMetadata.getIndicesLookup();
        Settings settings = Settings.builder().put(RoleBasedActionPrivileges.PRECOMPUTED_PRIVILEGES_ENABLED.getKey(), true).build();

        for (int i = 0; i < 100; i++) {
            // Build CompiledRoles once (as PrivilegesConfiguration would do)
            long startCompile = System.nanoTime();
            CompiledRoles compiledRoles = new CompiledRoles(roles, actionGroups, xContentRegistry, FieldMasking.Config.DEFAULT);
            long compileMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startCompile);

            // Build DocumentPrivileges (constructs StatefulRules internally via StatefulRules constructor)
            long startStateful = System.nanoTime();
            DocumentPrivileges subject = new DocumentPrivileges(compiledRoles, indicesLookup, NamedXContentRegistry.EMPTY, settings);
            long statefulMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startStateful);

            System.out.printf(
                "[constructionPerformance_sharedPatterns] iter=%d  CompiledRoles=%dms  DocumentPrivileges(StatefulRules)=%dms  total=%dms%n",
                i,
                compileMs,
                statefulMs,
                compileMs + statefulMs
            );

            // Verify correctness: role_0_user should have a DLS restriction on role_0_data
            User user = new User("test_user").withAttributes(Map.of("attr.internal.should_hide", "true"));
            PrivilegesEvaluationContext ctx = new PrivilegesEvaluationContext(
                user,
                ImmutableSet.of("role_0_user"),
                null,
                null,
                null,
                null,
                null,
                () -> clusterState,
                null
            );
            DlsRestriction restriction = subject.getRestriction(ctx, "role_0_data");
            assertNotNull("DLS restriction must not be null for role_0_data", restriction);
            // The role has a DLS query, so the index should NOT be unrestricted
            assertFalse("role_0_user should have a DLS restriction on role_0_data", restriction.isUnrestricted());
        }
    }
}
