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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.unit.ByteSizeUnit;
import org.opensearch.core.common.unit.ByteSizeValue;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.threadpool.ThreadPool;

import com.selectivem.collections.CheckTable;
import com.selectivem.collections.CompactMapGroupBuilder;
import com.selectivem.collections.DeduplicatingCompactSubSetBuilder;
import com.selectivem.collections.ImmutableCompactSubSet;

/**
 * This class converts role configuration into pre-computed, optimized data structures for checking privileges.
 * <p>
 * With the exception of the statefulIndex property, instances of this class are immutable. The life-cycle of an
 * instance of this class corresponds to the life-cycle of the role and action group configuration. If the role or
 * action group configuration is changed, a new instance needs to be built.
 */
public class ActionPrivileges {

    /**
     * This setting controls the allowed heap size of the precomputed index privileges (in the inner class StatefulIndexPrivileges).
     * If the size of the indices exceed the amount of bytes configured here, it will be truncated. Privileges evaluation will
     * continue to work correctly, but it will be slower.
     * <p>
     * This settings defaults to 10 MB. This is a generous limit. Experiments have shown that an example setup with
     * 10,000 indices and 1,000 roles requires about 1 MB of heap. 100,000 indices and 100 roles require about 9 MB of heap.
     * (Of course, these numbers can vary widely based on the actual role configuration).
     * <p>
     * The setting plugins.security.privileges_evaluation.precomputed_privileges.include_indices can be used to control
     * for which indices the precomputed privileges shall be created. This allows to lower the heap utilization.
     */
    public static Setting<ByteSizeValue> PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE = Setting.memorySizeSetting(
        "plugins.security.privileges_evaluation.precomputed_privileges.max_heap_size",
        new ByteSizeValue(10, ByteSizeUnit.MB),
        Setting.Property.NodeScope
    );

    /**
     * Determines the indices which shall be included in the precomputed index privileges. Included indices get
     * the fasted privilege evaluation.
     * <p>
     * You can use patterns like "index_*".
     * <p>
     * Defaults to all indices.
     */
    public static Setting<String> PRECOMPUTED_PRIVILEGES_INCLUDE_INDICES = Setting.simpleString(
        "plugins.security.privileges_evaluation.precomputed_privileges.include_indices",
        Setting.Property.NodeScope
    );

    private static final Logger log = LogManager.getLogger(ActionPrivileges.class);

    private final ClusterPrivileges cluster;
    private final IndexPrivileges index;
    private final SecurityDynamicConfiguration<RoleV7> roles;
    private final FlattenedActionGroups actionGroups;
    private final ImmutableSet<String> wellKnownClusterActions;
    private final ImmutableSet<String> wellKnownIndexActions;
    private final Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier;
    private final ByteSizeValue statefulIndexMaxHeapSize;
    private final WildcardMatcher statefulIndexIncludeIndices;

    private final AtomicReference<StatefulIndexPrivileges> statefulIndex = new AtomicReference<>();

    private Future<?> updateFuture;

    public ActionPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        FlattenedActionGroups actionGroups,
        Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier,
        Settings settings,
        ImmutableSet<String> wellKnownClusterActions,
        ImmutableSet<String> wellKnownIndexActions,
        ImmutableSet<String> explicitlyRequiredIndexActions
    ) {
        this.cluster = new ClusterPrivileges(roles, actionGroups, wellKnownClusterActions);
        this.index = new IndexPrivileges(roles, actionGroups, wellKnownIndexActions, explicitlyRequiredIndexActions);
        this.roles = roles;
        this.actionGroups = actionGroups;
        this.wellKnownClusterActions = wellKnownClusterActions;
        this.wellKnownIndexActions = wellKnownIndexActions;
        this.indexMetadataSupplier = indexMetadataSupplier;
        this.statefulIndexMaxHeapSize = PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE.get(settings);
        String statefulIndexIncludeIndices = PRECOMPUTED_PRIVILEGES_INCLUDE_INDICES.get(settings);
        this.statefulIndexIncludeIndices = Strings.isNullOrEmpty(statefulIndexIncludeIndices)
            ? null
            : WildcardMatcher.from(statefulIndexIncludeIndices);
    }

    public ActionPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        FlattenedActionGroups actionGroups,
        Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier,
        Settings settings
    ) {
        this(
            roles,
            actionGroups,
            indexMetadataSupplier,
            settings,
            WellKnownActions.CLUSTER_ACTIONS,
            WellKnownActions.INDEX_ACTIONS,
            WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS
        );
    }

    public PrivilegesEvaluatorResponse hasClusterPrivilege(PrivilegesEvaluationContext context, String action) {
        return cluster.providesPrivilege(context, action, context.getMappedRoles());
    }

    public PrivilegesEvaluatorResponse hasAnyClusterPrivilege(PrivilegesEvaluationContext context, Set<String> actions) {
        return cluster.providesAnyPrivilege(context, actions, context.getMappedRoles());
    }

    /**
     * Checks whether this instance provides explicit privileges for the combination of the provided action and the
     * provided roles.
     * <p>
     * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
     * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
     * <p>
     * Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
     * Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
     */
    public PrivilegesEvaluatorResponse hasExplicitClusterPrivilege(PrivilegesEvaluationContext context, String action) {
        return cluster.providesExplicitPrivilege(context, action, context.getMappedRoles());
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
     */
    public PrivilegesEvaluatorResponse hasIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        IndexResolverReplacer.Resolved resolvedIndices
    ) {
        PrivilegesEvaluatorResponse response = this.index.providesWildcardPrivilege(context, actions);
        if (response != null) {
            return response;
        }

        if (!resolvedIndices.isLocalAll() && resolvedIndices.getAllIndices().isEmpty()) {
            // This is necessary for requests which operate on remote indices.
            // Access control for the remote indices will be performed on the remote cluster.
            log.debug("No local indices; grant the request");
            return PrivilegesEvaluatorResponse.ok();
        }

        // TODO one might want to consider to create a semantic wrapper for action in order to be better tell apart
        // what's the action and what's the index in the generic parameters of CheckTable.
        CheckTable<String, String> checkTable = CheckTable.create(
            resolvedIndices.getAllIndicesResolved(context.getClusterStateSupplier(), context.getIndexNameExpressionResolver()),
            actions
        );

        StatefulIndexPrivileges statefulIndex = this.statefulIndex.get();
        PrivilegesEvaluatorResponse resultFromStatefulIndex = null;

        Map<String, IndexAbstraction> indexMetadata = this.indexMetadataSupplier.get();

        if (statefulIndex != null) {
            resultFromStatefulIndex = statefulIndex.providesPrivilege(actions, resolvedIndices, context, checkTable, indexMetadata);

            if (resultFromStatefulIndex != null) {
                // If we get a result from statefulIndex, we are done.
                return resultFromStatefulIndex;
            }

            // Otherwise, we need to carry on checking privileges using the non-stateful object.
            // Note: statefulIndex.hasPermission() modifies as a side effect the checkTable.
            // We can carry on using this as an intermediate result and further complete checkTable below.
        }

        return this.index.providesPrivilege(context, actions, resolvedIndices, checkTable, indexMetadata);
    }

    /**
     * Checks whether this instance provides explicit privileges for the combination of the provided action,
     * the provided indices and the provided roles.
     * <p>
     * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
     * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
     */
    public PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        IndexResolverReplacer.Resolved resolvedIndices
    ) {
        CheckTable<String, String> checkTable = CheckTable.create(resolvedIndices.getAllIndices(), actions);
        return this.index.providesExplicitPrivilege(context, actions, resolvedIndices, checkTable, this.indexMetadataSupplier.get());
    }

    /**
     * Updates the stateful index configuration with the given indices. Should be normally only called by
     * updateStatefulIndexPrivilegesAsync(). Package visible for testing.
     */
    void updateStatefulIndexPrivileges(Map<String, IndexAbstraction> indices, long metadataVersion) {
        StatefulIndexPrivileges statefulIndex = this.statefulIndex.get();

        indices = StatefulIndexPrivileges.relevantOnly(indices, statefulIndexIncludeIndices);

        if (statefulIndex == null || !statefulIndex.indices.equals(indices)) {
            long start = System.currentTimeMillis();
            this.statefulIndex.set(
                new StatefulIndexPrivileges(roles, actionGroups, wellKnownIndexActions, indices, metadataVersion, statefulIndexMaxHeapSize)
            );
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

    /**
     * Updates the stateful index configuration asynchronously with the index metadata from the current cluster state.
     * As the update process can take some seconds for clusters with many indices, this method "de-bounces" the updates,
     * i.e., a further update will be only initiated after the previous update has finished. This is okay as this class
     * can handle the case that it do not have the most recent information. It will fall back to slower methods then.
     */
    public synchronized void updateStatefulIndexPrivilegesAsync(ClusterService clusterService, ThreadPool threadPool) {
        long currentMetadataVersion = clusterService.state().metadata().version();

        StatefulIndexPrivileges statefulIndex = this.statefulIndex.get();

        if (statefulIndex != null && currentMetadataVersion <= statefulIndex.metadataVersion) {
            return;
        }

        if (this.updateFuture == null || this.updateFuture.isDone()) {
            this.updateFuture = threadPool.generic().submit(() -> {
                for (int i = 0;; i++) {
                    if (i > 10) {
                        try {
                            // In case we got many consecutive updates, let's sleep a little to let
                            // other operations catch up.
                            Thread.sleep(100);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }

                    Metadata metadata = clusterService.state().metadata();

                    synchronized (ActionPrivileges.this) {
                        if (metadata.version() <= ActionPrivileges.this.statefulIndex.get().metadataVersion) {
                            return;
                        }
                    }

                    try {
                        log.debug("Updating ActionPrivileges with metadata version {}", metadata.version());
                        updateStatefulIndexPrivileges(metadata.getIndicesLookup(), metadata.version());
                    } catch (Exception e) {
                        log.error("Error while updating ActionPrivileges", e);
                    } finally {
                        synchronized (ActionPrivileges.this) {
                            if (ActionPrivileges.this.updateFuture.isCancelled()) {
                                return;
                            }
                        }
                    }
                }
            });
        }
    }

    /**
     * Stops any concurrent update tasks to let the node gracefully shut down.
     */
    public synchronized void shutdown() {
        if (this.updateFuture != null && !this.updateFuture.isDone()) {
            this.updateFuture.cancel(true);
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
                                wellKnownClusterActions,
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
            ImmutableCompactSubSet<String> rolesWithPrivileges = this.actionToRoles.get(action);

            if (rolesWithPrivileges != null && rolesWithPrivileges.containsAny(roles)) {
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

        /**
         * Checks whether this instance provides explicit privileges for the combination of the provided action and the
         * provided roles.
         * <p>
         * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
         * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
         * <p>
         * Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
         * Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
         */
        PrivilegesEvaluatorResponse providesExplicitPrivilege(PrivilegesEvaluationContext context, String action, Set<String> roles) {

            // 1: Check well-known actions - this should cover most cases
            ImmutableCompactSubSet<String> rolesWithPrivileges = this.actionToRoles.get(action);

            if (rolesWithPrivileges != null && rolesWithPrivileges.containsAny(roles)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Only if everything else fails: Check the matchers in case we have a non-well-known action
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

        /**
         * Checks whether this instance provides privileges for the combination of any of the provided actions and the
         * provided roles. Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
         * Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
         */
        PrivilegesEvaluatorResponse providesAnyPrivilege(PrivilegesEvaluationContext context, Set<String> actions, Set<String> roles) {
            // 1: Check roles with wildcards
            if (CollectionUtils.containsAny(roles, this.rolesWithWildcardPermissions)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Check well-known actions - this should cover most cases
            for (String action : actions) {
                ImmutableCompactSubSet<String> rolesWithPrivileges = this.actionToRoles.get(action);

                if (rolesWithPrivileges != null && rolesWithPrivileges.containsAny(roles)) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }

            // 3: Only if everything else fails: Check the matchers in case we have a non-well-known action
            for (String action : actions) {
                if (!this.wellKnownClusterActions.contains(action)) {
                    for (String role : roles) {
                        WildcardMatcher matcher = this.rolesToActionMatcher.get(role);

                        if (matcher != null && matcher.test(action)) {
                            return PrivilegesEvaluatorResponse.ok();
                        }
                    }
                }
            }

            if (actions.size() == 1) {
                return PrivilegesEvaluatorResponse.insufficient(actions.iterator().next(), context);
            } else {
                return PrivilegesEvaluatorResponse.insufficient("any of " + actions, context);
            }
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
        private final ImmutableMap<String, ImmutableCompactSubSet<String>> actionToRolesWithWildcardIndexPrivileges;

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
            ImmutableSet<String> wellKnownIndexActions,
            ImmutableSet<String> explicitlyRequiredIndexActions
        ) {
            DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(
                roles.getCEntries().keySet()
            );

            Map<String, Map<String, IndexPattern.Builder>> rolesToActionToIndexPattern = new HashMap<>();
            Map<String, Map<WildcardMatcher, IndexPattern.Builder>> rolesToActionPatternToIndexPattern = new HashMap<>();
            Map<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> actionToRolesWithWildcardIndexPrivileges = new HashMap<>();
            Map<String, Map<String, IndexPattern.Builder>> rolesToExplicitActionToIndexPattern = new HashMap<>();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
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

                                if (explicitlyRequiredIndexActions.contains(permission)) {
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

                                for (String action : actionMatcher.iterateMatching(wellKnownIndexActions)) {
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
            List<PrivilegesEvaluationException> exceptions = new ArrayList<>();

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
                                    exceptions.add(new PrivilegesEvaluationException("Error while evaluating role " + role, e));
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
                                            log.error("Error while evaluating index pattern of role {}. Ignoring entry", role, e);
                                            exceptions.add(new PrivilegesEvaluationException("Error while evaluating role " + role, e));
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
                return PrivilegesEvaluatorResponse.partiallyOk(availableIndices, checkTable, context).evaluationExceptions(exceptions);
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable, context)
                .reason(
                    resolvedIndices.getAllIndices().size() == 1
                        ? "Insufficient permissions for the referenced index"
                        : "None of " + resolvedIndices.getAllIndices().size() + " referenced indices has sufficient permissions"
                )
                .evaluationExceptions(exceptions);
        }

        /**
         * Returns PrivilegesEvaluatorResponse.ok() if the user identified in the context object has privileges for all
         * indices (using *) for the given actions. Returns null otherwise. Then, further checks must be done to check
         * the user's privileges.
         */
        PrivilegesEvaluatorResponse providesWildcardPrivilege(PrivilegesEvaluationContext context, Set<String> actions) {
            ImmutableSet<String> effectiveRoles = context.getMappedRoles();

            for (String action : actions) {
                ImmutableCompactSubSet<String> rolesWithWildcardIndexPrivileges = this.actionToRolesWithWildcardIndexPrivileges.get(action);

                if (rolesWithWildcardIndexPrivileges == null || !rolesWithWildcardIndexPrivileges.containsAny(effectiveRoles)) {
                    return null;
                }
            }

            return PrivilegesEvaluatorResponse.ok();
        }

        /**
         * Checks whether this instance provides explicit privileges for the combination of the provided action,
         * the provided indices and the provided roles.
         * <p>
         * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
         * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
         */
        PrivilegesEvaluatorResponse providesExplicitPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            IndexResolverReplacer.Resolved resolvedIndices,
            CheckTable<String, String> checkTable,
            Map<String, IndexAbstraction> indexMetadata
        ) {
            List<PrivilegesEvaluationException> exceptions = new ArrayList<>();

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
                                    exceptions.add(new PrivilegesEvaluationException("Error while evaluating role " + role, e));
                                }
                            }
                        }
                    }
                }
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable, context)
                .reason("No explicit privileges have been provided for the referenced indices.")
                .evaluationExceptions(exceptions);
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
        private final Map<String, Map<String, ImmutableCompactSubSet<String>>> actionToIndexToRoles;

        /**
         * The index information that was used to construct this instance.
         */
        private final Map<String, IndexAbstraction> indices;

        /**
         * The well known index actions that were used to construct this instance.
         */
        private final ImmutableSet<String> wellKnownIndexActions;

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
            ImmutableSet<String> wellKnownIndexActions,
            Map<String, IndexAbstraction> indices,
            long metadataVersion,
            ByteSizeValue statefulIndexMaxHeapSize
        ) {
            Map<
                String,
                CompactMapGroupBuilder.MapBuilder<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>>> actionToIndexToRoles =
                    new HashMap<>();
            DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(
                roles.getCEntries().keySet()
            );
            CompactMapGroupBuilder<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> indexMapBuilder =
                new CompactMapGroupBuilder<>(indices.keySet(), (k2) -> roleSetBuilder.createSubSetBuilder());

            top: for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    roleSetBuilder.next(roleName);

                    for (RoleV7.Index indexPermissions : role.getIndex_permissions()) {
                        ImmutableSet<String> permissions = actionGroups.resolve(indexPermissions.getAllowed_actions());

                        if (indexPermissions.getIndex_patterns().contains("*")) {
                            // Wildcard index patterns are handled in the static IndexPermissions object.
                            continue;
                        }

                        WildcardMatcher indexMatcher = IndexPattern.from(indexPermissions.getIndex_patterns()).getStaticPattern();

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
                                    CompactMapGroupBuilder.MapBuilder<
                                        String,
                                        DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> indexToRoles = actionToIndexToRoles
                                            .computeIfAbsent(action, k -> indexMapBuilder.createMapBuilder());

                                    indexToRoles.get(indicesEntry.getKey()).add(roleName);

                                    if (indicesEntry.getValue() instanceof IndexAbstraction.Alias) {
                                        // For aliases we additionally add the sub-indices to the privilege map
                                        for (IndexMetadata subIndex : indicesEntry.getValue().getIndices()) {
                                            indexToRoles.get(subIndex.getIndex().getName()).add(roleName);
                                        }
                                    }

                                    if (roleSetBuilder.getEstimatedByteSize() + indexMapBuilder
                                        .getEstimatedByteSize() > statefulIndexMaxHeapSize.getBytes()) {
                                        log.info(
                                            "Size of precomputed index privileges exceeds configured limit ({}). Using capped data structure."
                                                + "This might lead to slightly lower performance during privilege evaluation. Consider raising {} or limiting the performance critical indices using {}.",
                                            statefulIndexMaxHeapSize,
                                            PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE.getKey(),
                                            PRECOMPUTED_PRIVILEGES_INCLUDE_INDICES.getKey()
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
            CheckTable<String, String> checkTable,
            Map<String, IndexAbstraction> indexMetadata
        ) {
            ImmutableSet<String> effectiveRoles = context.getMappedRoles();

            for (String action : actions) {
                Map<String, ImmutableCompactSubSet<String>> indexToRoles = actionToIndexToRoles.get(action);

                if (indexToRoles != null) {
                    for (String index : resolvedIndices.getAllIndices()) {
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
         *     <li>Indices which are not matched by includeIndices
         * </ul>
         */
        static Map<String, IndexAbstraction> relevantOnly(Map<String, IndexAbstraction> indices, WildcardMatcher includeIndices) {
            // First pass: Check if we need to filter at all
            boolean doFilter = false;

            for (IndexAbstraction indexAbstraction : indices.values()) {
                if (includeIndices != null && !includeIndices.test(indexAbstraction.getName())) {
                    doFilter = true;
                    break;
                }

                if (indexAbstraction instanceof IndexAbstraction.Index) {
                    if (indexAbstraction.getParentDataStream() != null
                        || indexAbstraction.getWriteIndex().getState() == IndexMetadata.State.CLOSE) {
                        doFilter = true;
                        break;
                    }
                }
            }

            if (!doFilter) {
                return indices;
            }

            // Second pass: Only if we actually need filtering, we will do it
            ImmutableMap.Builder<String, IndexAbstraction> builder = ImmutableMap.builder();

            for (IndexAbstraction indexAbstraction : indices.values()) {
                if (includeIndices != null && !includeIndices.test(indexAbstraction.getName())) {
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

}
