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
package org.opensearch.security.privileges;

import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.WellKnownActions;
import org.opensearch.security.privileges.dlsfls.DocumentPrivileges;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.privileges.dlsfls.FieldPrivileges;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;

/**
 * A compiled, pre-processed view of all roles. Instances of this class are immutable.
 * <p>
 * This class converts the raw {@link RoleV7} configuration into optimized data structures by resolving
 * action groups and compiling index/action patterns upfront.
 * <p>
 * Instances are shared between {@link RoleBasedActionPrivileges} and the DLS/FLS privilege classes (via
 * {@code DlsFlsProcessedConfig}) so that the compilation work is done only once per configuration update.
 */
public class CompiledRoles {

    public static final CompiledRoles EMPTY = new CompiledRoles(
        SecurityDynamicConfiguration.empty(CType.ROLES),
        FlattenedActionGroups.EMPTY,
        new NamedXContentRegistry(List.of()),
        FieldMasking.Config.DEFAULT,
        false
    );

    private static final Logger log = LogManager.getLogger(CompiledRoles.class);

    /**
     * Maps role names to their compiled {@link Role} representation.
     */
    public final ImmutableMap<String, Role> roles;

    /**
     * Creates a {@link CompiledRoles} instance from raw role configuration and resolved action groups.
     *
     * @param rolesConfig  the raw role configuration
     * @param actionGroups the flattened/resolved action groups to use for resolving action patterns
     */
    public CompiledRoles(
        SecurityDynamicConfiguration<RoleV7> rolesConfig,
        FlattenedActionGroups actionGroups,
        NamedXContentRegistry xContentRegistry,
        FieldMasking.Config fieldMaskingConfig,
        boolean memberIndexPrivilegesYieldAliasPrivileges
    ) {
        ImmutableMap.Builder<String, Role> rolesBuilder = ImmutableMap.builder();

        for (Map.Entry<String, RoleV7> entry : rolesConfig.getCEntries().entrySet()) {
            try {
                rolesBuilder.put(
                    entry.getKey(),
                    new Role(
                        entry.getKey(),
                        entry.getValue(),
                        actionGroups,
                        xContentRegistry,
                        fieldMaskingConfig,
                        memberIndexPrivilegesYieldAliasPrivileges
                    )
                );
            } catch (Exception e) {
                log.error("Unexpected exception while compiling role: {}\nIgnoring role.", entry.getKey(), e);
            }
        }

        this.roles = rolesBuilder.build();
    }

    /**
     * A compiled representation of a single role, corresponding to {@link RoleV7}.
     * <p>
     * Action group references in cluster and index permissions are resolved and compiled into
     * {@link WildcardMatcher} instances upfront.
     */
    public static class Role {
        /**
         * The raw underlying role configuration.
         */
        public final RoleV7 base;

        /**
         * The resolved set of cluster permission patterns (after action group expansion).
         */
        public final ImmutableSet<String> clusterPermissions;

        /**
         * A matcher compiled from the resolved cluster permissions. Can be used to check whether
         * a given action is covered by this role's cluster privileges.
         */
        public final WildcardMatcher clusterPermissionsMatcher;

        /**
         * The compiled index permission entries for this role.
         */
        public final ImmutableList<Index> indexPermissions;

        public Role(
            String roleName,
            RoleV7 base,
            FlattenedActionGroups actionGroups,
            NamedXContentRegistry xContentRegistry,
            FieldMasking.Config fieldMaskingConfig,
            boolean memberIndexPrivilegesYieldAliasPrivileges
        ) {
            this.base = base;
            this.clusterPermissions = actionGroups.resolve(base.getCluster_permissions());
            this.clusterPermissionsMatcher = WildcardMatcher.from(this.clusterPermissions);

            ImmutableList.Builder<Index> compiledIndexPermissions = ImmutableList.builderWithExpectedSize(
                base.getIndex_permissions().size()
            );
            for (RoleV7.Index rawIndex : base.getIndex_permissions()) {
                compiledIndexPermissions.add(
                    new Index(
                        roleName,
                        rawIndex,
                        actionGroups,
                        xContentRegistry,
                        fieldMaskingConfig,
                        memberIndexPrivilegesYieldAliasPrivileges
                    )
                );
            }
            this.indexPermissions = compiledIndexPermissions.build();
        }

        /**
         * A compiled representation of an index permission entry ({@link RoleV7.Index}).
         * <p>
         * The {@code index_patterns} list is compiled into an {@link IndexPattern}. The {@code allowed_actions}
         * list is resolved via action groups and compiled into a {@link WildcardMatcher}. Additionally,
         * the matcher is applied against the set of well-known index actions to produce a pre-computed
         * set {@link #allowedWellKnownActions} for fast lookup.
         */
        public static class Index {
            /**
             * The raw underlying index permission entry. Retained so that DLS/FLS rule functions
             * can be applied against it (e.g. extracting the DLS query or FLS field list).
             */
            public final RoleV7.Index rawIndex;

            /**
             * The compiled index pattern, built from the raw {@code index_patterns} list.
             */
            public final IndexPattern indexPattern;

            /**
             * The resolved and compiled action matcher, built from the raw {@code allowed_actions} list
             * after passing through the action group resolver.
             */
            public final WildcardMatcher allowedActionsMatcher;

            /**
             * The resolved set of actions (after action group expansion), prior to compilation into a matcher.
             */
            public final ImmutableSet<String> resolvedActions;

            /**
             * The subset of {@link WellKnownActions#INDEX_ACTIONS} that are matched by
             * {@link #allowedActionsMatcher}.
             */
            public final ImmutableSet<String> allowedWellKnownActions;

            /**
             * The document-level security (DLS) query string, or {@code null} if none is configured.
             */
            public final DocumentPrivileges.DlsQuery dls;

            /**
             * The field-level security (FLS) field list.
             */
            public final FieldPrivileges.FlsRule fls;

            /**
             * The masked fields list.
             */
            public final FieldMasking.FieldMaskingRule.SimpleRule maskedFields;

            public Index(
                String roleName,
                RoleV7.Index rawIndex,
                FlattenedActionGroups actionGroups,
                NamedXContentRegistry xContentRegistry,
                FieldMasking.Config fieldMaskingConfig,
                boolean memberIndexPrivilegesYieldAliasPrivileges
            ) {
                this.rawIndex = rawIndex;
                this.indexPattern = IndexPattern.from(rawIndex.getIndex_patterns(), memberIndexPrivilegesYieldAliasPrivileges);

                this.resolvedActions = actionGroups.resolve(rawIndex.getAllowed_actions());
                this.allowedActionsMatcher = WildcardMatcher.from(this.resolvedActions);
                this.allowedWellKnownActions = allowedActionsMatcher.getMatchAny(
                    WellKnownActions.INDEX_ACTIONS,
                    ImmutableSet.toImmutableSet()
                );

                this.dls = createDlsQuery(roleName, rawIndex, xContentRegistry);
                this.fls = createFlsRule(roleName, rawIndex);
                this.maskedFields = createFieldMaskingRule(roleName, rawIndex, fieldMaskingConfig);
            }

            static DocumentPrivileges.DlsQuery createDlsQuery(
                String roleName,
                RoleV7.Index rawIndex,
                NamedXContentRegistry xContentRegistry
            ) {
                try {
                    if (rawIndex.getDls() != null) {
                        return DocumentPrivileges.DlsQuery.create(rawIndex.getDls(), xContentRegistry);
                    } else {
                        return null;
                    }
                } catch (PrivilegesConfigurationValidationException e) {
                    log.error(
                        "Invalid DLS query for role '{}': {}\nIgnoring DLS configuration for this index permission.",
                        roleName,
                        rawIndex.getDls(),
                        e
                    );
                    return null;
                }
            }

            static FieldPrivileges.FlsRule createFlsRule(String roleName, RoleV7.Index rawIndex) {
                try {
                    if (rawIndex.getFls() != null && !rawIndex.getFls().isEmpty()) {
                        return FieldPrivileges.FlsRule.from(rawIndex);
                    } else {
                        return null;
                    }
                } catch (PrivilegesConfigurationValidationException e) {
                    log.error(
                        "Invalid FLS rule for role '{}': {}\nIgnoring FLS configuration for this index permission.",
                        roleName,
                        rawIndex.getFls(),
                        e
                    );
                    return null;
                }
            }

            static FieldMasking.FieldMaskingRule.SimpleRule createFieldMaskingRule(
                String roleName,
                RoleV7.Index rawIndex,
                FieldMasking.Config fieldMaskingConfig
            ) {
                try {
                    if (rawIndex.getMasked_fields() != null && !rawIndex.getMasked_fields().isEmpty()) {
                        return new FieldMasking.FieldMaskingRule.SimpleRule(rawIndex, fieldMaskingConfig);
                    } else {
                        return null;
                    }
                } catch (PrivilegesConfigurationValidationException e) {
                    log.error(
                        "Invalid field masking rule for role '{}': {}\nIgnoring field masking configuration for this index permission.",
                        roleName,
                        rawIndex.getMasked_fields(),
                        e
                    );
                    return null;
                }
            }
        }
    }
}
