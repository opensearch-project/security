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

package org.opensearch.security.privileges.actionlevel;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.unit.ByteSizeUnit;
import org.opensearch.core.common.unit.ByteSizeValue;
import org.opensearch.security.privileges.ClusterStateMetadataDependentPrivileges;
import org.opensearch.security.privileges.IndexPattern;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.collections.CheckTable;
import com.selectivem.collections.CompactMapGroupBuilder;
import com.selectivem.collections.DeduplicatingCompactSubSetBuilder;
import com.selectivem.collections.ImmutableCompactSubSet;

import static org.opensearch.security.privileges.actionlevel.WellKnownActions.allWellKnownIndexActions;

/**
 * This class converts role configuration into pre-computed, optimized data structures for checking privileges.
 * <p>
 * With the exception of the statefulIndex property, instances of this class are immutable. The life-cycle of an
 * instance of this class corresponds to the life-cycle of the role and action group configuration. If the role or
 * action group configuration is changed, a new instance needs to be built.
 */
public class RoleBasedActionPrivileges extends RuntimeOptimizedActionPrivileges {

    /**
     * This setting controls the allowed heap size of the precomputed index privileges (in the inner class StatefulIndexPrivileges).
     * If the size of the indices exceed the amount of bytes configured here, it will be truncated. Privileges evaluation will
     * continue to work correctly, but it will be slower.
     * <p>
     * This settings defaults to 10 MB. This is a generous limit. Experiments have shown that an example setup with
     * 10,000 indices and 1,000 roles requires about 1 MB of heap. 100,000 indices and 100 roles require about 9 MB of heap.
     * (Of course, these numbers can vary widely based on the actual role configuration).
     */
    public static Setting<ByteSizeValue> PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE = Setting.memorySizeSetting(
        "plugins.security.privileges_evaluation.precomputed_privileges.max_heap_size",
        new ByteSizeValue(10, ByteSizeUnit.MB),
        Setting.Property.NodeScope
    );

    /**
     * This setting controls whether the precomputed/denormalized index privileges (in the inner class StatefulIndexPrivileges)
     * will be created or not. This is on by default to provide the best action throughput. It can make sense to
     * disable this when it is seen that the initialisation process takes so much time/resources that it negatively
     * affects the cluster performance. This come at the price of a reduced action throughput.
     */
    public static Setting<Boolean> PRECOMPUTED_PRIVILEGES_ENABLED = Setting.boolSetting(
        "plugins.security.privileges_evaluation.precomputed_privileges.enabled",
        true,
        Setting.Property.NodeScope
    );

    private static final Logger log = LogManager.getLogger(RoleBasedActionPrivileges.class);

    private final SecurityDynamicConfiguration<RoleV7> roles;
    private final FlattenedActionGroups actionGroups;
    private final ByteSizeValue statefulIndexMaxHeapSize;
    private final boolean statefulIndexEnabled;

    private final AtomicReference<StatefulIndexPrivileges> statefulIndex = new AtomicReference<>();

    /**
     * Creates a new RoleBasedActionPrivileges instance based on the given parameters.
     *
     * @param roles the roles form the basis for the privilege configuration
     * @param actionGroups the action groups will be used to expand the "allowed_actions" attributes in the roles config
     * @param specialIndexProtection configuration that identifies indices for which additional protections should be applied
     * @param settings Other settings for this instance. The settings PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE and PRECOMPUTED_PRIVILEGES_ENABLED
     *                 will be read from this.
     */
    public RoleBasedActionPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        FlattenedActionGroups actionGroups,
        SpecialIndexProtection specialIndexProtection,
        Settings settings
    ) {
        super(new ClusterPrivileges(roles, actionGroups), new IndexPrivileges(roles, actionGroups, specialIndexProtection));
        this.roles = roles;
        this.actionGroups = actionGroups;
        this.statefulIndexMaxHeapSize = PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE.get(settings);
        this.statefulIndexEnabled = PRECOMPUTED_PRIVILEGES_ENABLED.get(settings);
    }

    /**
     * Updates the stateful index configuration with the given indices. This should be only used in two situations:
     * <ul>
     *     <li>A new instance of RoleBasedActionPrivileges is created</li>
     *     <li>The cluster state changes</li>
     * </ul>
     * On large clusters this update can take a time in the magnitude of 1000 ms to complete. Thus, calling
     * the async method updateStatefulIndexPrivilegesAsync(). Should be preferred.
     */
    public void updateStatefulIndexPrivileges(Map<String, IndexAbstraction> indices, long metadataVersion) {
        if (!this.statefulIndexEnabled) {
            return;
        }

        StatefulIndexPrivileges statefulIndex = this.statefulIndex.get();

        indices = StatefulIndexPrivileges.relevantOnly(indices, this.index.universallyDeniedIndices);

        if (statefulIndex == null || !statefulIndex.indices.equals(indices)) {
            long start = System.currentTimeMillis();
            this.statefulIndex.set(new StatefulIndexPrivileges(roles, actionGroups, indices, metadataVersion, statefulIndexMaxHeapSize));
            long duration = System.currentTimeMillis() - start;
            log.debug("Updating StatefulIndexPrivileges took {} ms", duration);
        } else {
            synchronized (this) {
                // Even if the indices did not change, update the metadataVersion in statefulIndex to reflect
                // that the instance is up-to-date.
                if (statefulIndex.metadataVersion < metadataVersion) {
                    statefulIndex.metadataVersion = metadataVersion;
                }
            }
        }
    }

    int getEstimatedStatefulIndexByteSize() {
        StatefulIndexPrivileges statefulIndex = this.statefulIndex.get();

        if (statefulIndex != null) {
            return statefulIndex.estimatedByteSize;
        } else {
            return 0;
        }
    }

    @Override
    protected RuntimeOptimizedActionPrivileges.StatefulIndexPrivileges currentStatefulIndexPrivileges() {
        return this.statefulIndex.get();
    }

    public ClusterStateMetadataDependentPrivileges clusterStateMetadataDependentPrivileges() {
        return this.clusterStateMetadataDependentPrivileges;
    }

    /**
     * Pre-computed, optimized cluster privilege maps. Instances of this class are immutable.
     * <p>
     * The data structures in this class are optimized for answering the question
     * "I have action A and roles [x,y,z]. Do I have authorization to execute the action?".
     * <p>
     * The check will be possible in time O(1) for "well-known" actions when the user actually has the privileges.
     */
    static class ClusterPrivileges extends RuntimeOptimizedActionPrivileges.ClusterPrivileges {

        /**
         * Maps names of actions to the roles that provide a privilege for the respective action.
         * Note that the mapping is not comprehensive, additionally the data structures rolesWithWildcardPermissions
         * and rolesToActionMatcher need to be considered for a full view of the privileges.
         * <p>
         * This does not include privileges obtained via "*" action patterns. This is both meant as a
         * optimization and to support explicit privileges.
         */
        private final ImmutableMap<String, ImmutableCompactSubSet<String>> actionToRoles;

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
         *
         * This does not include privileges obtained via "*" action patterns. This is both meant as a
         * optimization and to support explicit privileges.
         */
        private final ImmutableMap<String, WildcardMatcher> rolesToActionMatcher;

        /**
         * Creates pre-computed cluster privileges based on the given parameters.
         * <p>
         * This constructor will not throw an exception if it encounters any invalid configuration (that is,
         * in particular, unparseable regular expressions). Rather, it will just log an error. This is okay, as it
         * just results in fewer available privileges. However, having a proper error reporting mechanism would be
         * kind of nice.
         */
        ClusterPrivileges(SecurityDynamicConfiguration<RoleV7> roles, FlattenedActionGroups actionGroups) {
            DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(
                roles.getCEntries().keySet()
            );
            Map<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> actionToRoles = new HashMap<>();
            ImmutableSet.Builder<String> rolesWithWildcardPermissions = ImmutableSet.builder();
            ImmutableMap.Builder<String, WildcardMatcher> rolesToActionMatcher = ImmutableMap.builder();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    roleSetBuilder.next(roleName);

                    ImmutableSet<String> permissionPatterns = actionGroups.resolve(role.getCluster_permissions());

                    // This list collects all the matchers for action names that will be found for the current role
                    List<WildcardMatcher> wildcardMatchers = new ArrayList<>();

                    for (String permission : permissionPatterns) {
                        // If we have a permission which does not use any pattern, we just simply add it to the
                        // "actionToRoles" map.
                        // Otherwise, we match the pattern against the provided well-known cluster actions and add
                        // these to the "actionToRoles" map. Additionally, for the case that the well-known cluster
                        // actions are not complete, we also collect the matcher to be used as a last resort later.

                        if (WildcardMatcher.isExact(permission)) {
                            actionToRoles.computeIfAbsent(permission, k -> roleSetBuilder.createSubSetBuilder()).add(roleName);
                        } else if (permission.equals("*")) {
                            // Special case: Roles with a wildcard "*" giving privileges for all actions. We will not resolve
                            // this stuff, but just note separately that this role just gets all the cluster privileges.
                            rolesWithWildcardPermissions.add(roleName);
                        } else {
                            WildcardMatcher wildcardMatcher = WildcardMatcher.from(permission);
                            Set<String> matchedActions = wildcardMatcher.getMatchAny(
                                WellKnownActions.CLUSTER_ACTIONS,
                                Collectors.toUnmodifiableSet()
                            );

                            for (String action : matchedActions) {
                                actionToRoles.computeIfAbsent(action, k -> roleSetBuilder.createSubSetBuilder()).add(roleName);
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

            DeduplicatingCompactSubSetBuilder.Completed<String> completedRoleSetBuilder = roleSetBuilder.build();

            this.actionToRoles = actionToRoles.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry -> entry.getValue().build(completedRoleSetBuilder)));
            this.rolesWithWildcardPermissions = rolesWithWildcardPermissions.build();
            this.rolesToActionMatcher = rolesToActionMatcher.build();
        }

        @Override
        protected boolean checkWildcardPrivilege(PrivilegesEvaluationContext context) {
            return CollectionUtils.containsAny(context.getMappedRoles(), this.rolesWithWildcardPermissions);
        }

        @Override
        protected boolean checkPrivilegeForWellKnownAction(PrivilegesEvaluationContext context, String action) {
            ImmutableCompactSubSet<String> rolesWithPrivileges = this.actionToRoles.get(action);
            return rolesWithPrivileges != null && rolesWithPrivileges.containsAny(context.getMappedRoles());
        }

        @Override
        protected boolean checkPrivilegeViaActionMatcher(PrivilegesEvaluationContext context, String action) {
            if (!WellKnownActions.CLUSTER_ACTIONS.contains(action)) {
                for (String role : context.getMappedRoles()) {
                    WildcardMatcher matcher = this.rolesToActionMatcher.get(role);

                    if (matcher != null && matcher.test(action)) {
                        return true;
                    }
                }
            }

            return false;
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
    static class IndexPrivileges extends RuntimeOptimizedActionPrivileges.StaticIndexPrivileges {
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
        private final ImmutableMap<String, ImmutableCompactSubSet<String>> actionToRolesWithWildcardIndexPrivileges;

        /**
         * Maps role names to concrete action names to IndexPattern objects which define the indices the privileges apply to.
         * The action names are only explicitly granted privileges which are listed in explicitlyRequiredIndexActions.
         * <p>
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
            SpecialIndexProtection specialIndexProtection
        ) {
            super(specialIndexProtection);

            Map<String, Map<String, IndexPattern.Builder>> rolesToActionToIndexPattern = new HashMap<>();
            Map<String, Map<WildcardMatcher, IndexPattern.Builder>> rolesToActionPatternToIndexPattern = new HashMap<>();
            Map<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> actionToRolesWithWildcardIndexPrivileges = new HashMap<>();
            Map<String, Map<String, IndexPattern.Builder>> rolesToExplicitActionToIndexPattern = new HashMap<>();

            Map<String, RoleV7> permissionEntries = roles.getCEntries();

            DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(permissionEntries.keySet());

            for (Map.Entry<String, RoleV7> entry : permissionEntries.entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    roleSetBuilder.next(roleName);

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

                                if (WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS.contains(permission)) {
                                    rolesToExplicitActionToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .computeIfAbsent(permission, k -> new IndexPattern.Builder())
                                        .add(indexPermissions.getIndex_patterns());
                                }

                                if (indexPermissions.getIndex_patterns().contains("*")) {
                                    actionToRolesWithWildcardIndexPrivileges.computeIfAbsent(
                                        permission,
                                        k -> roleSetBuilder.createSubSetBuilder()
                                    ).add(roleName);
                                }
                            } else {
                                WildcardMatcher actionMatcher = WildcardMatcher.from(permission);

                                for (String action : actionMatcher.iterateMatching(WellKnownActions.INDEX_ACTIONS)) {
                                    rolesToActionToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .computeIfAbsent(action, k -> new IndexPattern.Builder())
                                        .add(indexPermissions.getIndex_patterns());

                                    if (indexPermissions.getIndex_patterns().contains("*")) {
                                        actionToRolesWithWildcardIndexPrivileges.computeIfAbsent(
                                            permission,
                                            k -> roleSetBuilder.createSubSetBuilder()
                                        ).add(roleName);
                                    }
                                }

                                rolesToActionPatternToIndexPattern.computeIfAbsent(roleName, k -> new HashMap<>())
                                    .computeIfAbsent(actionMatcher, k -> new IndexPattern.Builder())
                                    .add(indexPermissions.getIndex_patterns());

                                if (actionMatcher != WildcardMatcher.ANY) {
                                    for (String action : actionMatcher.iterateMatching(
                                        WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS
                                    )) {
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

            DeduplicatingCompactSubSetBuilder.Completed<String> completedRoleSetBuilder = roleSetBuilder.build();

            this.rolesToActionToIndexPattern = rolesToActionToIndexPattern.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue()
                            .entrySet()
                            .stream()
                            .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry2 -> entry2.getValue().build()))
                    )
                );

            this.rolesToActionPatternToIndexPattern = rolesToActionPatternToIndexPattern.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue()
                            .entrySet()
                            .stream()
                            .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry2 -> entry2.getValue().build()))
                    )
                );

            this.actionToRolesWithWildcardIndexPrivileges = actionToRolesWithWildcardIndexPrivileges.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry -> entry.getValue().build(completedRoleSetBuilder)));

            this.rolesToExplicitActionToIndexPattern = rolesToExplicitActionToIndexPattern.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue()
                            .entrySet()
                            .stream()
                            .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry2 -> entry2.getValue().build()))
                    )
                );

        }

        /**
         * Checks whether this instance provides privileges for the combination of the provided action,
         * the provided indices and the provided roles.
         * <p>
         * Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
         * <p>
         * If privileges are only available for a sub-set of indices, isPartiallyOk() will return true
         * and the indices for which privileges are available are returned by getAvailableIndices(). This allows the
         * do_not_fail_on_forbidden behaviour.
         * <p>
         * This method will only verify privileges for the index/action combinations which are un-checked in
         * the checkTable instance provided to this method. Checked index/action combinations are considered to be
         * "already fulfilled by other means" - usually that comes from the stateful data structure.
         * As a side-effect, this method will further mark the available index/action combinations in the provided
         * checkTable instance as checked.
         */
        @Override
        protected IntermediateResult providesPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable
        ) {
            List<PrivilegesEvaluationException> exceptions = new ArrayList<>();

            for (String role : context.getMappedRoles()) {
                ImmutableMap<String, IndexPattern> actionToIndexPattern = this.rolesToActionToIndexPattern.get(role);
                if (actionToIndexPattern != null) {
                    checkPrivilegeWithIndexPatternOnWellKnownActions(context, actions, checkTable, actionToIndexPattern, exceptions);
                    if (checkTable.isComplete()) {
                        return new IntermediateResult(checkTable).evaluationExceptions(exceptions);
                    }
                }
            }

            // If all actions are well-known, the index.rolesToActionToIndexPattern data structure that was evaluated above,
            // would have contained all the actions if privileges are provided. If there are non-well-known actions among the
            // actions, we also have to evaluate action patterns to check the authorization

            if (!checkTable.isComplete() && !allWellKnownIndexActions(actions)) {
                for (String role : context.getMappedRoles()) {
                    ImmutableMap<WildcardMatcher, IndexPattern> actionPatternToIndexPattern = this.rolesToActionPatternToIndexPattern.get(
                        role
                    );

                    if (actionPatternToIndexPattern != null) {
                        checkPrivilegesForNonWellKnownActions(context, actions, checkTable, actionPatternToIndexPattern, exceptions);
                        if (checkTable.isComplete()) {
                            return new IntermediateResult(checkTable).evaluationExceptions(exceptions);
                        }
                    }
                }
            }

            return new IntermediateResult(checkTable).evaluationExceptions(exceptions);
        }

        /**
         * Returns IntermediateResult.ok() if the user identified in the context object has privileges for all
         * indices (using *) for the given actions. Returns null otherwise. Then, further checks must be done to check
         * the user's privileges.
         * <p>
         * As a side-effect, this method will mark the available index/action combinations in the provided
         * checkTable instance as checked.
         */
        @Override
        protected IntermediateResult checkWildcardIndexPrivilegesOnWellKnownActions(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable
        ) {
            ImmutableSet<String> effectiveRoles = context.getMappedRoles();

            for (String action : actions) {
                ImmutableCompactSubSet<String> rolesWithWildcardIndexPrivileges = this.actionToRolesWithWildcardIndexPrivileges.get(action);

                if (rolesWithWildcardIndexPrivileges != null && rolesWithWildcardIndexPrivileges.containsAny(effectiveRoles)) {
                    checkTable.checkIf(index -> true, action);
                }
            }

            if (checkTable.isComplete()) {
                return new IntermediateResult(checkTable);
            } else {
                return null;
            }
        }

        /**
         * Checks whether this instance provides explicit privileges for the combination of the provided action,
         * the provided indices and the provided roles.
         * <p>
         * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
         * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
         */
        @Override
        protected PrivilegesEvaluatorResponse providesExplicitPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable
        ) {
            Map<String, IndexAbstraction> indexMetadata = context.getIndicesLookup();
            List<PrivilegesEvaluationException> exceptions = new ArrayList<>();

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
                                    exceptions.add(new PrivilegesEvaluationException("Error while evaluating role " + role, e));
                                }
                            }
                        }
                    }
                }
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable)
                .reason("No explicit privileges have been provided for the referenced indices.")
                .evaluationExceptions(exceptions);
        }

        @Override
        protected boolean providesExplicitPrivilege(
            PrivilegesEvaluationContext context,
            String index,
            String action,
            List<PrivilegesEvaluationException> exceptions
        ) {
            Map<String, IndexAbstraction> indexMetadata = context.getIndicesLookup();

            for (String role : context.getMappedRoles()) {
                ImmutableMap<String, IndexPattern> actionToIndexPattern = this.rolesToExplicitActionToIndexPattern.get(role);

                if (actionToIndexPattern != null) {
                    IndexPattern indexPattern = actionToIndexPattern.get(action);

                    if (indexPattern != null) {
                        try {
                            if (indexPattern.matches(index, context, indexMetadata)) {
                                return true;
                            }
                        } catch (PrivilegesEvaluationException e) {
                            // We can ignore these errors, as this max leads to fewer privileges than available
                            log.error("Error while evaluating index pattern of role {}. Ignoring entry", role, e);
                            exceptions.add(new PrivilegesEvaluationException("Error while evaluating role " + role, e));
                        }

                    }
                }

            }

            return false;
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
    static class StatefulIndexPrivileges extends RuntimeOptimizedActionPrivileges.StatefulIndexPrivileges {

        /**
         * Maps concrete action names to concrete index names and then to the roles which provide privileges for the
         * combination of action and index. This map can contain besides indices also names of data streams and aliases.
         * For aliases and data streams, it will then contain both the actual alias/data stream and the backing indices.
         */
        private final Map<String, Map<String, ImmutableCompactSubSet<String>>> actionToIndexToRoles;

        /**
         * The index information that was used to construct this instance.
         */
        private final Map<String, IndexAbstraction> indices;

        private final int estimatedByteSize;

        private long metadataVersion;

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
            Map<String, IndexAbstraction> indices,
            long metadataVersion,
            ByteSizeValue statefulIndexMaxHeapSize
        ) {
            long startTime = System.currentTimeMillis();

            Map<
                String,
                CompactMapGroupBuilder.MapBuilder<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>>> actionToIndexToRoles =
                    new HashMap<>();
            DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(
                roles.getCEntries().keySet()
            );
            CompactMapGroupBuilder<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> indexMapBuilder =
                new CompactMapGroupBuilder<>(indices.keySet(), (k2) -> roleSetBuilder.createSubSetBuilder());

            // We iterate here through the present RoleV7 instances and nested through their "index_permissions" sections.
            // During the loop, the actionToIndexToRoles map is being built.
            // For that, action patterns from the role will be matched against the "well-known actions" to build
            // a concrete action map and index patterns from the role will be matched against the present indices
            // to build a concrete index map.
            //
            // The complexity of this loop is O(n*m) where n is dependent on the structure of the roles configuration
            // and m is the number of matched indices. This formula does not take the loop through matchedActions in
            // account, as this is bound by a constant number and thus does not need to be considered in the O() notation.

            top: for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    roleSetBuilder.next(roleName);

                    for (RoleV7.Index indexPermissions : role.getIndex_permissions()) {
                        ImmutableSet<String> permissions = actionGroups.resolve(indexPermissions.getAllowed_actions());

                        if (indexPermissions.getIndex_patterns().contains("*")) {
                            // Wildcard index patterns are handled in the static IndexPermissions object.
                            // This avoids having to build huge data structures - when a very easy shortcut is available.
                            continue;
                        }

                        WildcardMatcher indexMatcher = IndexPattern.from(indexPermissions.getIndex_patterns()).getStaticPattern();

                        if (indexMatcher == WildcardMatcher.NONE) {
                            // The pattern is likely blank because there are only templated patterns.
                            // Index patterns with templates are not handled here, but in the static IndexPermissions object
                            continue;
                        }

                        List<IndexAbstraction> matchingIndices = indexMatcher.matching(indices.values(), IndexAbstraction::getName);
                        if (matchingIndices.isEmpty()) {
                            continue;
                        }

                        for (String permission : permissions) {
                            WildcardMatcher actionMatcher = WildcardMatcher.from(permission);
                            Collection<String> matchedActions = actionMatcher.getMatchAny(
                                WellKnownActions.INDEX_ACTIONS,
                                Collectors.toList()
                            );

                            for (IndexAbstraction index : matchingIndices) {
                                for (String action : matchedActions) {
                                    CompactMapGroupBuilder.MapBuilder<
                                        String,
                                        DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> indexToRoles = actionToIndexToRoles
                                            .computeIfAbsent(action, k -> indexMapBuilder.createMapBuilder());

                                    indexToRoles.get(index.getName()).add(roleName);

                                    if (index instanceof IndexAbstraction.Alias) {
                                        // For aliases we additionally add the sub-indices to the privilege map
                                        for (IndexMetadata subIndex : index.getIndices()) {
                                            String subIndexName = subIndex.getIndex().getName();
                                            // We need to check whether the subIndex is part of the global indices
                                            // metadata map because that map has been filtered by relevantOnly().
                                            // This method removes all closed indices and data stream backing indices
                                            // because these indices get a separate treatment. However, these indices
                                            // might still appear as member indices of aliases. Trying to add these
                                            // to the SubSetBuilder indexToRoles would result in an IllegalArgumentException
                                            // because the subIndex will not be part of the super set.
                                            if (indices.containsKey(subIndexName)) {
                                                indexToRoles.get(subIndexName).add(roleName);
                                            } else {
                                                log.debug(
                                                    "Ignoring member index {} of alias {}. This is usually the case because the index is closed or a data stream backing index.",
                                                    subIndexName,
                                                    index.getName()
                                                );
                                            }
                                        }
                                    }

                                    if (roleSetBuilder.getEstimatedByteSize() + indexMapBuilder
                                        .getEstimatedByteSize() > statefulIndexMaxHeapSize.getBytes()) {
                                        log.info(
                                            "Size of precomputed index privileges exceeds configured limit ({}). Using capped data structure."
                                                + "This might lead to slightly lower performance during privilege evaluation. Consider raising {}.",
                                            statefulIndexMaxHeapSize,
                                            PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE.getKey()
                                        );
                                        break top;
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry.getKey(), e);
                }
            }

            DeduplicatingCompactSubSetBuilder.Completed<String> completedRoleSetBuilder = roleSetBuilder.build();

            this.estimatedByteSize = roleSetBuilder.getEstimatedByteSize() + indexMapBuilder.getEstimatedByteSize();
            log.debug("Estimated size of StatefulIndexPermissions data structure: {}", this.estimatedByteSize);

            this.actionToIndexToRoles = actionToIndexToRoles.entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().build(subSetBuilder -> subSetBuilder.build(completedRoleSetBuilder))
                    )
                );

            this.indices = ImmutableMap.copyOf(indices);
            this.metadataVersion = metadataVersion;

            long duration = System.currentTimeMillis() - startTime;

            if (duration > 30000) {
                log.warn("Creation of StatefulIndexPrivileges took {} ms", duration);
            } else {
                log.debug("Creation of StatefulIndexPrivileges took {} ms", duration);
            }
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
         * @param context         context information like user, resolved roles, etc.
         * @param checkTable      An action/index matrix. This method will modify the table as a side effect and check the cells where privileges are present.
         * @return PrivilegesEvaluatorResponse.ok() or null.
         */
        @Override
        protected IntermediateResult providesPrivilege(
            Set<String> actions,
            PrivilegesEvaluationContext context,
            CheckTable<String, String> checkTable
        ) {
            Map<String, IndexAbstraction> indexMetadata = context.getIndicesLookup();
            ImmutableSet<String> effectiveRoles = context.getMappedRoles();
            Set<String> indices = checkTable.getRows();

            for (String action : actions) {
                Map<String, ImmutableCompactSubSet<String>> indexToRoles = actionToIndexToRoles.get(action);

                if (indexToRoles != null) {
                    for (String index : indices) {
                        String lookupIndex = index;

                        if (index.startsWith(DataStream.BACKING_INDEX_PREFIX)) {
                            // If we have a backing index of a data stream, we will not try to test
                            // the backing index here, as we filter backing indices during initialization.
                            // Instead, we look up the containing data stream and check whether this has privileges.
                            lookupIndex = backingIndexToDataStream(index, indexMetadata);
                        }

                        ImmutableCompactSubSet<String> rolesWithPrivileges = indexToRoles.get(lookupIndex);

                        if (rolesWithPrivileges != null && rolesWithPrivileges.containsAny(effectiveRoles)) {
                            if (checkTable.check(index, action)) {
                                return new IntermediateResult(checkTable);
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

        /**
         * If the given index is the backing index of a data stream, the name of the data stream is returned.
         * Otherwise, the name of the index itself is being returned.
         */
        static String backingIndexToDataStream(String index, Map<String, IndexAbstraction> indexMetadata) {
            IndexAbstraction indexAbstraction = indexMetadata.get(index);

            if (indexAbstraction instanceof IndexAbstraction.Index && indexAbstraction.getParentDataStream() != null) {
                return indexAbstraction.getParentDataStream().getName();
            } else {
                return index;
            }
        }

        /**
         * Filters the given index abstraction map to only contain entries that are relevant the for stateful class.
         * This has the goal to keep the heap footprint of instances of StatefulIndexPrivileges at a reasonable size.
         * <p>
         * This removes the following entries:
         * <ul>
         *     <li>closed indices - closed indices do not need any fast privilege evaluation
         *     <li>backing indices of data streams - privileges should be only assigned directly to the data streams.
         *       the privilege evaluation code is able to recognize that an index is member of a data stream and test
         *       its privilege via that data stream. If a privilege is directly assigned to a backing index, we use
         *       the "slowish" code paths.
         *     <li>Indices which are universally denied
         * </ul>
         */
        static Map<String, IndexAbstraction> relevantOnly(
            Map<String, IndexAbstraction> indices,
            Predicate<String> universallyDeniedIndices
        ) {
            ImmutableMap.Builder<String, IndexAbstraction> builder = ImmutableMap.builder();

            for (IndexAbstraction indexAbstraction : indices.values()) {
                if (universallyDeniedIndices.test(indexAbstraction.getName())) {
                    continue;
                }

                if (indexAbstraction instanceof IndexAbstraction.Index) {
                    if (indexAbstraction.getParentDataStream() == null
                        && indexAbstraction.getWriteIndex().getState() != IndexMetadata.State.CLOSE) {
                        builder.put(indexAbstraction.getName(), indexAbstraction);
                    }
                } else {
                    builder.put(indexAbstraction.getName(), indexAbstraction);
                }
            }

            return builder.build();
        }
    }

    final ClusterStateMetadataDependentPrivileges clusterStateMetadataDependentPrivileges = new ClusterStateMetadataDependentPrivileges() {
        @Override
        protected void updateClusterStateMetadata(Metadata metadata) {
            RoleBasedActionPrivileges.this.updateStatefulIndexPrivileges(metadata.getIndicesLookup(), metadata.version());
        }

        @Override
        protected long getCurrentlyUsedMetadataVersion() {
            StatefulIndexPrivileges statefulIndex = RoleBasedActionPrivileges.this.statefulIndex.get();
            return statefulIndex != null ? statefulIndex.metadataVersion : 0;
        }
    };

    public FlattenedActionGroups flattenedActionGroups() {
        return actionGroups;
    }
}
