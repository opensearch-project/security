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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.check.CheckTable;

/**
 * This class converts role configuration into pre-computed, optimized data structures for checking privileges.
 *
 * With the exception of the statefulIndex property, instances of this class are immutable. The life-cycle of an
 * instance of this class corresponds to the life-cycle of the role and action group configuration. If the role or
 * action group configuration is changed, a new instance needs to be built.
 *
 * TODO:
 *
 * - At the moment, only RolesV7 configurations are supported
 * - At the moment, it always behaves like dcm.isMultiRolespanEnabled() is true
 * - Cap the size of StatefulIndexPrivileges and have a kind of LRU cache
 * - Extract interface to make this pluggable (requested in https://github.com/opensearch-project/security/issues/3870#issuecomment-1910286322)
 * - Implement DLS/FLS.
 * - In the end, this class is intended to replace the SecurityRoles class. This class and references to it should be
 * then removed.
 */
public class ActionPrivileges {
    private static final Logger log = LogManager.getLogger(ActionPrivileges.class);

    private final ClusterPrivileges cluster;
    private final IndexPrivileges index;
    private final SecurityDynamicConfiguration<RoleV7> roles;
    private final FlattenedActionGroups actionGroups;
    private final ImmutableSet<String> wellKnownClusterActions;
    private final ImmutableSet<String> wellKnownIndexActions;
    private final Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier;

    private volatile StatefulIndexPrivileges statefulIndex;

    /**
     * TODO: It is not nice that we cannot use SecurityDynamicConfiguration<?> with a concrete generic parameter
     */
    public ActionPrivileges(
        SecurityDynamicConfiguration<?> rolesUnsafe,
        FlattenedActionGroups actionGroups,
        Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier,
        ImmutableSet<String> wellKnownClusterActions,
        ImmutableSet<String> wellKnownIndexActions,
        ImmutableSet<String> explicitlyRequiredIndexActions
    ) {
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<RoleV7> roles = (SecurityDynamicConfiguration<RoleV7>) rolesUnsafe;
        this.cluster = new ClusterPrivileges(roles, actionGroups, wellKnownClusterActions);
        this.index = new IndexPrivileges(roles, actionGroups, wellKnownIndexActions, explicitlyRequiredIndexActions);
        this.roles = roles;
        this.actionGroups = actionGroups;
        this.wellKnownClusterActions = wellKnownClusterActions;
        this.wellKnownIndexActions = wellKnownIndexActions;
        this.indexMetadataSupplier = indexMetadataSupplier;
    }

    public ActionPrivileges(
        SecurityDynamicConfiguration<?> roles,
        FlattenedActionGroups actionGroups,
        Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier
    ) {
        this(
            roles,
            actionGroups,
            indexMetadataSupplier,
            WellKnownActions.CLUSTER_ACTIONS,
            WellKnownActions.INDEX_ACTIONS,
            WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS
        );
    }

    public PrivilegesEvaluatorResponse hasClusterPrivilege(PrivilegesEvaluationContext context, String action) {
        return cluster.providesPrivilege(context, action, context.getMappedRoles());
    }

    public PrivilegesEvaluatorResponse hasIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        IndexResolverReplacer.Resolved resolvedIndices
    ) {
        if (resolvedIndices.isLocalAll()) {
            PrivilegesEvaluatorResponse response = this.index.providesWildcardPrivilege(context, actions);

            if (response != null) {
                return response;
            }
        }

        if (resolvedIndices.getAllIndices().isEmpty()) {
            log.debug("No local indices; grant the request");
            return PrivilegesEvaluatorResponse.ok();
        }

        // TODO one might want to consider to create a semantic wrapper for action in order to be better tell apart
        // what's the action and what's the index in the generic parameters of CheckTable.
        CheckTable<String, String> checkTable = CheckTable.create(
            resolvedIndices.getAllIndicesResolved(context.getClusterStateSupplier(), context.getIndexNameExpressionResolver()),
            actions
        );

        StatefulIndexPrivileges statefulIndex = this.statefulIndex;
        PrivilegesEvaluatorResponse resultFromStatefulIndex = null;

        if (statefulIndex != null) {
            resultFromStatefulIndex = statefulIndex.providesPrivilege(actions, resolvedIndices, context, checkTable);

            if (resultFromStatefulIndex != null) {
                // If we get a result from statefulIndex, we are done.
                return resultFromStatefulIndex;
            }

            // Otherwise, we need to carry on checking privileges using the non-stateful object.
            // Note: statefulIndex.hasPermission() modifies as a side effect the checkTable.
            // We can carry on using this as an intermediate result and further complete checkTable below.
        }

        return this.index.providesPrivilege(context, actions, resolvedIndices, checkTable, this.indexMetadataSupplier.get());
    }

    public PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        IndexResolverReplacer.Resolved resolvedIndices
    ) {
        CheckTable<String, String> checkTable = CheckTable.create(resolvedIndices.getAllIndices(), actions);
        return this.index.providesExplicitPrivilege(context, actions, resolvedIndices, checkTable, this.indexMetadataSupplier.get());
    }

    public void updateStatefulIndexPrivileges(Map<String, IndexAbstraction> indices) {
        StatefulIndexPrivileges statefulIndex = this.statefulIndex;

        if (statefulIndex == null || !statefulIndex.indices.equals(indices)) {
            this.statefulIndex = new StatefulIndexPrivileges(roles, actionGroups, wellKnownIndexActions, indices);
        }
    }

    /**
     * Pre-computed, optimized cluster privilege maps. Instances of this class are immutable.
     * <p>
     * The data structures in this class are optimized for answering the question
     * "I have action A and roles [x,y,z]. Do I have authorization to execute the action?".
     * <p>
     * The check will be possible in time O(1) for "well-known" actions when the user actually has the privileges.
     */
    static class ClusterPrivileges {

        /**
         * Maps names of actions to the roles that provide a privilege for the respective action.
         * Note that the mapping is not comprehensive, additionally the data structures rolesWithWildcardPermissions
         * and rolesToActionMatcher need to be considered for a full view of the privileges.
         */
        private final ImmutableMap<String, ImmutableSet<String>> actionToRoles;

        /**
         * This contains all role names that provide wildcard (*) privileges for cluster actions.
         * This avoids a blow-up of the actionToRoles object by such roles.
         */
        private final ImmutableSet<String> rolesWithWildcardPermissions;

        /**
         * This maps role names to a matcher which matches the action names this role provides privileges for.
         * This is only used as a last resort if the test with actionToRole and rolesWithWildcardPermissions failed.
         * This is only necessary for actions which are not contained in the list of "well-known" actions provided
         * during construction.
         */
        private final ImmutableMap<String, WildcardMatcher> rolesToActionMatcher;

        private final ImmutableSet<String> wellKnownClusterActions;

        /**
         * Creates pre-computed cluster privileges based on the given parameters.
         * <p>
         * This constructor will not throw an exception if it encounters any invalid configuration (that is,
         * in particular, unparseable regular expressions). Rather, it will just log an error. This is okay, as it
         * just results in fewer available privileges. However, having a proper error reporting mechanism would be
         * kind of nice.
         */
        ClusterPrivileges(
            SecurityDynamicConfiguration<RoleV7> roles,
            FlattenedActionGroups actionGroups,
            ImmutableSet<String> wellKnownClusterActions
        ) {
            Map<String, Set<String>> actionToRoles = new HashMap<>();
            ImmutableSet.Builder<String> rolesWithWildcardPermissions = ImmutableSet.builder();
            ImmutableMap.Builder<String, WildcardMatcher> rolesToActionMatcher = ImmutableMap.builder();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();
                    ImmutableSet<String> permissionPatterns = actionGroups.resolve(role.getCluster_permissions());

                    // This list collects all the matchers for action names that will be found for the current role
                    List<WildcardMatcher> wildcardMatchers = new ArrayList<>();

                    // Special case: Roles with a wildcard "*" giving privileges for all actions. We will not resolve
                    // this stuff, but just note separately that this role just gets all the cluster privileges.
                    if (permissionPatterns.contains("*")) {
                        rolesWithWildcardPermissions.add(roleName);
                        continue;
                    }

                    for (String permission : permissionPatterns) {
                        // If we have a permission which does not use any pattern, we just simply add it to the
                        // "actionToRoles" map.
                        // Otherwise, we match the pattern against the provided well-known cluster actions and add
                        // these to the "actionToRoles" map. Additionally, for the case that the well-known cluster
                        // actions are not complete, we also collect the matcher to be used as a last resort later.

                        if (WildcardMatcher.isExact(permission)) {
                            actionToRoles.computeIfAbsent(permission, k -> new HashSet<>()).add(roleName);
                        } else {
                            WildcardMatcher wildcardMatcher = WildcardMatcher.from(permission);
                            Set<String> matchedActions = wildcardMatcher.getMatchAny(
                                wellKnownClusterActions,
                                Collectors.toUnmodifiableSet()
                            );

                            for (String action : matchedActions) {
                                actionToRoles.computeIfAbsent(action, k -> new HashSet<>()).add(roleName);
                            }

                            wildcardMatchers.add(wildcardMatcher);
                        }
                    }

                    if (!wildcardMatchers.isEmpty()) {
                        rolesToActionMatcher.put(roleName, WildcardMatcher.from(wildcardMatchers));
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry.getKey(), e);
                }
            }

            this.actionToRoles = actionToRoles.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> ImmutableSet.copyOf(entry.getValue())));
            this.rolesWithWildcardPermissions = rolesWithWildcardPermissions.build();
            this.rolesToActionMatcher = rolesToActionMatcher.build();
            this.wellKnownClusterActions = wellKnownClusterActions;
        }

        /**
         * Checks whether this instance provides privileges for the combination of the provided action and the
         * provided roles. Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
         * Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
         */
        PrivilegesEvaluatorResponse providesPrivilege(PrivilegesEvaluationContext context, String action, Set<String> roles) {

            // 1: Check roles with wildcards
            if (CollectionUtils.containsAny(roles, this.rolesWithWildcardPermissions)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Check well-known actions - this should cover most cases
            ImmutableSet<String> rolesWithPrivileges = this.actionToRoles.get(action);

            if (rolesWithPrivileges != null && CollectionUtils.containsAny(roles, rolesWithPrivileges)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 3: Only if everything else fails: Check the matchers in case we have a non-well-known action
            if (!this.wellKnownClusterActions.contains(action)) {
                for (String role : roles) {
                    WildcardMatcher matcher = this.rolesToActionMatcher.get(role);

                    if (matcher != null && matcher.test(action)) {
                        return PrivilegesEvaluatorResponse.ok();
                    }
                }
            }

            return PrivilegesEvaluatorResponse.insufficient(action, context);
        }
    }

    /**
     * Partially pre-computed, optimized index privilege maps. Instances of this class are immutable.
     * <p>
     * This class is independent of the actual indices present in the cluster. See StatefulIndexPermissions for a class
     * that also takes actual indices into account and is thus fully pre-computed.
     * <p>
     * Purposes of this class:
     * <p>
     * 1. Answer the question "given an action and a set of roles, do I have wildcard index privileges" in O(1)
     * <p>
     * 2. Pre-compute the data structures as far as possible in cases that StatefulIndexPermissions cannot check the
     * permissions. This is the case when:
     * <p>
     * a) StatefulIndexPermissions does not cover all indices
     * b) The requested index does not exist (especially the case for create index actions)
     * c) The index patterns use placeholders like "${user.name}" - these can be only resolved when the User object is present.
     * d) The action is not among the "well known" actions.
     */
    static class IndexPrivileges {
        /**
         * Maps role names to concrete action names to IndexPattern objects which define the indices the privileges apply to.
         */
        private final ImmutableMap<String, ImmutableMap<String, IndexPattern>> rolesToActionToIndexPattern;

        /**
         * Maps role names to action names matchers to IndexPattern objects which define the indices the privileges apply to.
         * This is especially for "non-well-known" actions.
         */
        private final ImmutableMap<String, ImmutableMap<WildcardMatcher, IndexPattern>> rolesToActionPatternToIndexPattern;

        /**
         * Maps action names to the roles which provide wildcard ("*") index privileges for the respective action.
         * This allows to answer the question "given an action and a set of roles, do I have wildcard index privileges"
         * in O(1)
         */
        private final ImmutableMap<String, ImmutableSet<String>> actionToRolesWithWildcardIndexPrivileges;

        /**
         * A pre-defined set of action names that is used to pre-compute the result of action patterns.
         */
        private final ImmutableSet<String> wellKnownIndexActions;

        /**
         * A pre-defined set of action names that is included in the rolesToExplicitActionToIndexPattern data structure
         */
        private final ImmutableSet<String> explicitlyRequiredIndexActions;

        /**
         * Maps role names to concrete action names to IndexPattern objects which define the indices the privileges apply to.
         * The action names are only explicitly granted privileges which are listed in explicitlyRequiredIndexActions.
         *
         * Compare https://github.com/opensearch-project/security/pull/2887
         */
        private final ImmutableMap<String, ImmutableMap<String, IndexPattern>> rolesToExplicitActionToIndexPattern;

        /**
         * Creates pre-computed index privileges based on the given parameters.
         * <p>
         * This constructor will not throw an exception if it encounters any invalid configuration (that is,
         * in particular, unparseable regular expressions). Rather, it will just log an error. This is okay, as it
         * just results in fewer available privileges. However, having a proper error reporting mechanism would be
         * kind of nice.
         */
        IndexPrivileges(
            SecurityDynamicConfiguration<RoleV7> roles,
            FlattenedActionGroups actionGroups,
            ImmutableSet<String> wellKnownIndexActions,
            ImmutableSet<String> explicitlyRequiredIndexActions
        ) {
            Map<String, Map<String, IndexPattern.Builder>> rolesToActionToIndexPattern = new HashMap<>();
            Map<String, Map<WildcardMatcher, IndexPattern.Builder>> rolesToActionPatternToIndexPattern = new HashMap<>();
            Map<String, Set<String>> actionToRolesWithWildcardIndexPrivileges = new HashMap<>();
            Map<String, Map<String, IndexPattern.Builder>> rolesToExplicitActionToIndexPattern = new HashMap<>();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    for (RoleV7.Index indexPermissions : role.getIndex_permissions()) {
                        ImmutableSet<String> permissions = actionGroups.resolve(indexPermissions.getAllowed_actions());

                        for (String permission : permissions) {
                            // If we have a permission which does not use any pattern, we just simply add it to the
                            // "rolesToActionToIndexPattern" map.
                            // Otherwise, we match the pattern against the provided well-known index actions and add
                            // these to the "rolesToActionToIndexPattern" map. Additionally, for the case that the
                            // well-known index actions are not complete, we also collect the actionMatcher to be used
                            // as a last resort later.

                            if (WildcardMatcher.isExact(permission)) {
                                rolesToActionToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                    .computeIfAbsent(permission, k -> new IndexPattern.Builder())
                                    .add(indexPermissions.getIndex_patterns());

                                if (explicitlyRequiredIndexActions.contains(permission)) {
                                    rolesToExplicitActionToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .computeIfAbsent(permission, k -> new IndexPattern.Builder())
                                        .add(indexPermissions.getIndex_patterns());
                                }

                                if (indexPermissions.getIndex_patterns().contains("*")) {
                                    actionToRolesWithWildcardIndexPrivileges.computeIfAbsent(permission, k -> new HashSet<>())
                                        .add(roleName);
                                }
                            } else {
                                WildcardMatcher actionMatcher = WildcardMatcher.from(permission);

                                for (String action : actionMatcher.iterateMatching(wellKnownIndexActions)) {
                                    rolesToActionToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .computeIfAbsent(action, k -> new IndexPattern.Builder())
                                        .add(indexPermissions.getIndex_patterns());

                                    if (indexPermissions.getIndex_patterns().contains("*")) {
                                        actionToRolesWithWildcardIndexPrivileges.computeIfAbsent(permission, k -> new HashSet<>())
                                            .add(roleName);
                                    }
                                }

                                rolesToActionPatternToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                    .computeIfAbsent(actionMatcher, k -> new IndexPattern.Builder())
                                    .add(indexPermissions.getIndex_patterns());

                                if (actionMatcher != WildcardMatcher.ANY) {
                                    for (String action : actionMatcher.iterateMatching(explicitlyRequiredIndexActions)) {
                                        rolesToExplicitActionToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                            .computeIfAbsent(action, k -> new IndexPattern.Builder())
                                            .add(indexPermissions.getIndex_patterns());
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry.getKey(), e);
                }
            }

            this.rolesToActionToIndexPattern = rolesToActionToIndexPattern.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        entry -> entry.getKey(),
                        entry -> entry.getValue()
                            .entrySet()
                            .stream()
                            .collect(ImmutableMap.toImmutableMap(entry2 -> entry2.getKey(), entry2 -> entry2.getValue().build()))
                    )
                );

            this.rolesToActionPatternToIndexPattern = rolesToActionPatternToIndexPattern.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        entry -> entry.getKey(),
                        entry -> entry.getValue()
                            .entrySet()
                            .stream()
                            .collect(ImmutableMap.toImmutableMap(entry2 -> entry2.getKey(), entry2 -> entry2.getValue().build()))
                    )
                );

            this.actionToRolesWithWildcardIndexPrivileges = actionToRolesWithWildcardIndexPrivileges.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> ImmutableSet.copyOf(entry.getValue())));

            this.rolesToExplicitActionToIndexPattern = rolesToExplicitActionToIndexPattern.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        entry -> entry.getKey(),
                        entry -> entry.getValue()
                            .entrySet()
                            .stream()
                            .collect(ImmutableMap.toImmutableMap(entry2 -> entry2.getKey(), entry2 -> entry2.getValue().build()))
                    )
                );

            this.wellKnownIndexActions = wellKnownIndexActions;
            this.explicitlyRequiredIndexActions = explicitlyRequiredIndexActions;
        }

        PrivilegesEvaluatorResponse providesPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            IndexResolverReplacer.Resolved resolvedIndices,
            CheckTable<String, String> checkTable,
            Map<String, IndexAbstraction> indexMetadata
        ) {
            for (String role : context.getMappedRoles()) {
                ImmutableMap<String, IndexPattern> actionToIndexPattern = this.rolesToActionToIndexPattern.get(role);

                if (actionToIndexPattern != null) {
                    for (String action : actions) {
                        IndexPattern indexPattern = actionToIndexPattern.get(action);

                        if (indexPattern != null) {
                            for (String index : checkTable.iterateUncheckedRows(action)) {
                                try {
                                    if (indexPattern.matches(index, context, indexMetadata) && checkTable.check(index, action)) {
                                        return PrivilegesEvaluatorResponse.ok();
                                    }
                                } catch (PrivilegesEvaluationException e) {
                                    // We can ignore these errors, as this max leads to fewer privileges than available
                                    log.error("Error while evaluating index pattern of role {}. Ignoring entry", role, e);
                                }
                            }
                        }
                    }
                }
            }

            // If all actions are well-known, the index.rolesToActionToIndexPattern data structure that was evaluated above,
            // would have contained all the actions if privileges are provided. If there are non-well-known actions among the
            // actions, we also have to evaluate action patterns to check the authorization

            boolean allActionsWellKnown = actions.stream().allMatch(a -> this.wellKnownIndexActions.contains(a));

            if (!checkTable.isComplete() && !allActionsWellKnown) {
                top: for (String role : context.getMappedRoles()) {
                    ImmutableMap<WildcardMatcher, IndexPattern> actionPatternToIndexPattern = this.rolesToActionPatternToIndexPattern.get(
                        role
                    );

                    if (actionPatternToIndexPattern != null) {
                        for (String action : actions) {
                            if (this.wellKnownIndexActions.contains(action)) {
                                continue;
                            }

                            for (Map.Entry<WildcardMatcher, IndexPattern> entry : actionPatternToIndexPattern.entrySet()) {
                                WildcardMatcher actionMatcher = entry.getKey();
                                IndexPattern indexPattern = entry.getValue();

                                if (actionMatcher.test(action)) {
                                    for (String index : checkTable.iterateUncheckedRows(action)) {
                                        try {
                                            if (indexPattern.matches(index, context, indexMetadata) && checkTable.check(index, action)) {
                                                break top;
                                            }
                                        } catch (PrivilegesEvaluationException e) {
                                            // We can ignore these errors, as this max leads to fewer privileges than available
                                            log.error("Error while evaluating index pattern. Ignoring entry", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (checkTable.isComplete()) {
                return PrivilegesEvaluatorResponse.ok();
            }

            Set<String> availableIndices = checkTable.getCompleteRows();

            if (!availableIndices.isEmpty()) {
                return PrivilegesEvaluatorResponse.partiallyOk(availableIndices, checkTable, context);
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable, context)
                .reason(
                    resolvedIndices.getAllIndices().size() == 1
                        ? "Insufficient permissions for the referenced index"
                        : "None of " + resolvedIndices.getAllIndices().size() + " referenced indices has sufficient permissions"
                );
        }

        /**
         * Returns PrivilegesEvaluatorResponse.ok() if the user identified in the context object has privileges for all
         * indices (using *) for the given actions. Returns null otherwise. Then, further checks must be done to check
         * the user's privileges.
         */
        PrivilegesEvaluatorResponse providesWildcardPrivilege(PrivilegesEvaluationContext context, Set<String> actions) {
            ImmutableSet<String> effectiveRoles = context.getMappedRoles();
            CheckTable<String, String> checkTable = CheckTable.create(ImmutableSet.of("*"), actions);

            for (String action : actions) {
                ImmutableSet<String> rolesWithWildcardIndexPrivileges = this.actionToRolesWithWildcardIndexPrivileges.get(action);

                if (rolesWithWildcardIndexPrivileges != null
                    && CollectionUtils.containsAny(rolesWithWildcardIndexPrivileges, effectiveRoles)) {
                    if (checkTable.check("*", action)) {
                        return PrivilegesEvaluatorResponse.ok();
                    }
                }
            }

            return null;
        }

        PrivilegesEvaluatorResponse providesExplicitPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            IndexResolverReplacer.Resolved resolvedIndices,
            CheckTable<String, String> checkTable,
            Map<String, IndexAbstraction> indexMetadata
        ) {
            if (!CollectionUtils.containsAny(actions, this.explicitlyRequiredIndexActions)) {
                return PrivilegesEvaluatorResponse.insufficient(CheckTable.create(ImmutableSet.of("_"), actions), context);
            }

            for (String role : context.getMappedRoles()) {
                ImmutableMap<String, IndexPattern> actionToIndexPattern = this.rolesToExplicitActionToIndexPattern.get(role);

                if (actionToIndexPattern != null) {
                    for (String action : actions) {
                        IndexPattern indexPattern = actionToIndexPattern.get(action);

                        if (indexPattern != null) {
                            for (String index : checkTable.iterateUncheckedRows(action)) {
                                try {
                                    if (indexPattern.matches(index, context, indexMetadata) && checkTable.check(index, action)) {
                                        return PrivilegesEvaluatorResponse.ok();
                                    }
                                } catch (PrivilegesEvaluationException e) {
                                    // We can ignore these errors, as this max leads to fewer privileges than available
                                    log.error("Error while evaluating index pattern of role {}. Ignoring entry", role, e);
                                }
                            }
                        }
                    }
                }
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable, context)
                .reason(
                    resolvedIndices.getAllIndices().size() == 1
                        ? "Insufficient permissions for the referenced index"
                        : "None of " + resolvedIndices.getAllIndices().size() + " referenced indices has sufficient permissions"
                );
        }
    }

    /**
     * Fully pre-computed, optimized index privilege maps.
     * <p>
     * The data structures in this class are optimized to answer the question "given an action, an index and a set of
     * roles, do I have the respective privilege" in O(1).
     * <p>
     * There are cases where this class will not be able to answer this question. These cases are the following:
     * - The requested index does not exist (especially the case for create index actions)
     * - The action is not well-known.
     * - The indices used for pre-computing the data structures are not complete (possibly due to race conditions)
     * - The role definition uses placeholders (like "${user.name}") in index patterns.
     * - The role definition grants privileges to all indices (via "*") (these are omitted here for efficiency reasons).
     * In such cases, the question needs to be answered by IndexPermissions (see above).
     * <p>
     * This class also takes into account aliases and data streams. If a permission is granted on an alias, it will be
     * automatically inherited by the indices it points to. The same holds for the backing indices of a data stream.
     */
    static class StatefulIndexPrivileges {

        /**
         * Maps concrete action names to concrete index names and then to the roles which provide privileges for the
         * combination of action and index. This map can contain besides indices also names of data streams and aliases.
         * For aliases and data streams, it will then contain both the actual alias/data stream and the backing indices.
         */
        private final Map<String, Map<String, Set<String>>> actionToIndexToRoles;

        /**
         * The index information that was used to construct this instance.
         */
        private final Map<String, IndexAbstraction> indices;

        /**
         * The well known index actions that were used to construct this instance.
         */
        private final ImmutableSet<String> wellKnownIndexActions;

        /**
         * Creates pre-computed index privileges based on the given parameters.
         * <p>
         * This constructor will not throw an exception if it encounters any invalid configuration (that is,
         * in particular, unparseable regular expressions). Rather, it will just log an error. This is okay, as it
         * just results in fewer available privileges.
         */
        StatefulIndexPrivileges(
            SecurityDynamicConfiguration<RoleV7> roles,
            FlattenedActionGroups actionGroups,
            ImmutableSet<String> wellKnownIndexActions,
            Map<String, IndexAbstraction> indices
        ) {
            Map<String, Map<String, Set<String>>> actionToIndexToRoles = new HashMap<>();
            int leafs = 0; // This counts the number of leafs in the actionToIndexToRoles data structure. Useful for estimating the size.

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    for (RoleV7.Index indexPermissions : role.getIndex_permissions()) {
                        ImmutableSet<String> permissions = actionGroups.resolve(indexPermissions.getAllowed_actions());

                        if (indexPermissions.getIndex_patterns().contains("*")) {
                            // Wildcard index patterns are handled in the static IndexPermissions object.
                            continue;
                        }

                        WildcardMatcher indexMatcher = IndexPattern.from(indexPermissions.getIndex_patterns()).pattern;

                        if (indexMatcher == WildcardMatcher.NONE) {
                            // The pattern is likely blank because there are only templated patterns.
                            // Index patterns with templates are not handled here, but in the static IndexPermissions object
                            continue;
                        }

                        for (String permission : permissions) {
                            WildcardMatcher actionMatcher = WildcardMatcher.from(permission);
                            Collection<String> matchedActions = actionMatcher.getMatchAny(wellKnownIndexActions, Collectors.toList());

                            for (Map.Entry<String, IndexAbstraction> indicesEntry : indexMatcher.iterateMatching(
                                indices.entrySet(),
                                Map.Entry::getKey
                            )) {
                                for (String action : matchedActions) {
                                    Map<String, Set<String>> indexToRoles = actionToIndexToRoles.computeIfAbsent(
                                        action,
                                        k -> new HashMap<>()
                                    );

                                    indexToRoles.computeIfAbsent(indicesEntry.getKey(), k -> new HashSet<>()).add(roleName);
                                    leafs++;

                                    if (indicesEntry.getValue() instanceof IndexAbstraction.Alias
                                        || indicesEntry.getValue() instanceof IndexAbstraction.DataStream) {
                                        // For aliases or data streams, we additionally add the sub- or backing-
                                        // indices to the privilege map
                                        for (IndexMetadata subIndex : indicesEntry.getValue().getIndices()) {
                                            indexToRoles.computeIfAbsent(subIndex.getIndex().getName(), k -> new HashSet<>()).add(roleName);
                                            leafs++;
                                        }
                                        // TODO: Possible optimization: The number of data stream backing indices can
                                        // get quite large. However, it is relatively easy to deduce from an index that
                                        // it is a backing index. It would be possible to skip these indices here.
                                        // Instead, during privilege evaluation the containing data stream needs to be
                                        // retrieved and checked in addition to the backing index.
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry.getKey(), e);
                }
            }

            log.debug("StatefulIndexPermissions data structure contains {} leafs", leafs);

            this.actionToIndexToRoles = actionToIndexToRoles.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        entry -> entry.getKey(),
                        entry -> entry.getValue()
                            .entrySet()
                            .stream()
                            .collect(
                                ImmutableMap.toImmutableMap(entry2 -> entry2.getKey(), entry2 -> ImmutableSet.copyOf(entry2.getValue()))
                            )
                    )
                );

            this.indices = ImmutableMap.copyOf(indices);
            this.wellKnownIndexActions = wellKnownIndexActions;
        }

        /**
         * Checks whether the user has privileges based on the given parameters and information in this class. This method
         * has two major channels for returning results:
         * <p>
         * 1. The return value is either PrivilegesEvaluatorResponse.ok() or null. If it is null, this method cannot
         * completely tell whether the user has full privileges. A further check with IndexPermissions will be necessary.
         * If PrivilegesEvaluatorResponse.ok() is returned, then full privileges could be already determined.
         * <p>
         * 2. As a side effect, this method will modify the supplied CheckTable object. This will be the case regardless
         * of whether null or PrivilegesEvaluatorResponse.ok() is returned. The interesting case is actually when null
         * is returned, because then the remaining logic needs only to check for the unchecked cases.
         *
         * @param actions         the actions the user needs to have privileges for
         * @param resolvedIndices the index the user needs to have privileges for
         * @param context         context information like user, resolved roles, etc.
         * @param checkTable      An action/index matrix. This method will modify the table as a side effect and check the cells where privileges are present.
         * @return PrivilegesEvaluatorResponse.ok() or null.
         */
        PrivilegesEvaluatorResponse providesPrivilege(
            Set<String> actions,
            IndexResolverReplacer.Resolved resolvedIndices,
            PrivilegesEvaluationContext context,
            CheckTable<String, String> checkTable
        ) {
            ImmutableSet<String> effectiveRoles = context.getMappedRoles();

            for (String action : actions) {
                Map<String, Set<String>> indexToRoles = actionToIndexToRoles.get(action);

                if (indexToRoles != null) {
                    for (String index : resolvedIndices.getAllIndices()) {
                        Set<String> rolesWithPrivileges = indexToRoles.get(index);

                        if (rolesWithPrivileges != null && CollectionUtils.containsAny(rolesWithPrivileges, effectiveRoles)) {
                            checkTable.check(index, action);
                            if (checkTable.isComplete()) {
                                return PrivilegesEvaluatorResponse.ok();
                            }
                        }
                    }
                }
            }

            // If we reached this point, we cannot tell whether the user has privileges using this instance.
            // Return null to indicate that there is no answer.
            // The checkTable object might contain already a partial result.
            return null;
        }
    }

    /**
     * Aggregates index patterns defined in roles and segments them into patterns using template expressions ("index_${user.name}"),
     * patterns using date math and plain patterns. This segmentation is needed because only plain patterns can be used
     * to pre-compute privilege maps. The other types of patterns need to be evaluated "live" during the actual request.
     */
    static class IndexPattern {

        private final WildcardMatcher pattern;
        private final ImmutableList<String> patternTemplates;
        private final ImmutableList<String> dateMathExpressions;

        IndexPattern(WildcardMatcher pattern, ImmutableList<String> patternTemplates, ImmutableList<String> dateMathExpressions) {
            this.pattern = pattern;
            this.patternTemplates = patternTemplates;
            this.dateMathExpressions = dateMathExpressions;
        }

        public boolean matches(String index, PrivilegesEvaluationContext context, Map<String, IndexAbstraction> indexMetadata)
            throws PrivilegesEvaluationException {
            if (pattern.test(index)) {
                return true;
            }

            if (!patternTemplates.isEmpty()) {
                for (String patternTemplate : this.patternTemplates) {
                    try {
                        WildcardMatcher matcher = context.getRenderedMatcher(patternTemplate);

                        if (matcher.test(index)) {
                            return true;
                        }
                    } catch (ExpressionEvaluationException e) {
                        throw new PrivilegesEvaluationException("Error while evaluating dynamic index pattern: " + patternTemplate, e);
                    }
                }
            }

            if (!dateMathExpressions.isEmpty()) {
                IndexNameExpressionResolver indexNameExpressionResolver = context.getIndexNameExpressionResolver();

                // Note: The use of date math expressions in privileges is a bit odd, as it only provides a very limited
                // solution for the potential user case. A different approach might be nice.

                for (String dateMathExpression : this.dateMathExpressions) {
                    try {
                        String resolvedExpression = indexNameExpressionResolver.resolveDateMathExpression(dateMathExpression);

                        if (!containsPlaceholder(resolvedExpression)) {
                            WildcardMatcher matcher = WildcardMatcher.from(resolvedExpression);

                            if (matcher.test(index)) {
                                return true;
                            }
                        } else {
                            WildcardMatcher matcher = context.getRenderedMatcher(resolvedExpression);

                            if (matcher.test(index)) {
                                return true;
                            }
                        }
                    } catch (Exception e) {
                        throw new PrivilegesEvaluationException("Error while evaluating date math expression: " + dateMathExpression, e);
                    }
                }
            }

            IndexAbstraction indexAbstraction = indexMetadata.get(index);

            if (indexAbstraction instanceof IndexAbstraction.Index) {
                // Check for the privilege for aliases or data streams containing this index

                if (indexAbstraction.getParentDataStream() != null) {
                    if (matches(indexAbstraction.getParentDataStream().getName(), context, indexMetadata)) {
                        return true;
                    }
                }

                // Retrieve aliases: The use of getWriteIndex() is a bit messy, but it is the only way to access
                // alias metadata from here.
                for (String alias : indexAbstraction.getWriteIndex().getAliases().keySet()) {
                    if (matches(alias, context, indexMetadata)) {
                        return true;
                    }
                }
            }

            return false;
        }

        @Override
        public String toString() {
            if (pattern != null && patternTemplates != null && patternTemplates.size() != 0) {
                return pattern + " " + patternTemplates;
            } else if (pattern != null) {
                return pattern.toString();
            } else if (patternTemplates != null) {
                return patternTemplates.toString();
            } else {
                return "-/-";
            }
        }

        static class Builder {
            private List<WildcardMatcher> constantPatterns = new ArrayList<>();
            private List<String> patternTemplates = new ArrayList<>();
            private List<String> dateMathExpressions = new ArrayList<>();
            private int initializationErrors = 0;

            void add(List<String> source) {
                for (int i = 0; i < source.size(); i++) {
                    try {
                        String indexPattern = source.get(i);

                        if (indexPattern.startsWith("<") && indexPattern.endsWith(">")) {
                            this.dateMathExpressions.add(indexPattern);
                        } else if (!containsPlaceholder(indexPattern)) {
                            this.constantPatterns.add(WildcardMatcher.from(indexPattern));
                        } else {
                            this.patternTemplates.add(indexPattern);
                        }
                    } catch (Exception e) {
                        // This usually happens when the index pattern defines an unparseable regular expression
                        log.error("Error while creating index pattern for {}", source, e);
                        this.initializationErrors++;
                    }
                }
            }

            IndexPattern build() {
                return new IndexPattern(
                    WildcardMatcher.from(constantPatterns),
                    ImmutableList.copyOf(patternTemplates),
                    ImmutableList.copyOf(dateMathExpressions)
                );
            }
        }

        static boolean containsPlaceholder(String indexPattern) {
            return indexPattern.indexOf("${") != -1;
        }

        static IndexPattern from(List<String> source) {
            Builder builder = new Builder();
            builder.add(source);
            return builder.build();
        }
    }
}
