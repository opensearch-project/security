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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.collections.CheckTable;

/**
 * An ActionPrivileges implementation that is valid only for a single subject.
 * This means that individual instances of this class must be created for individual subjects. The mapped roles
 * from the context are not regarded by this method.
 * <p>
 * The method PrivilegesEvaluator.createContext() is responsible for making sure that the correct class is used.
 * <p>
 * This class is useful for plugin users and API tokens.
 */
public class SubjectBasedActionPrivileges implements ActionPrivileges {
    private static final Logger log = LogManager.getLogger(SubjectBasedActionPrivileges.class);

    private final ClusterPrivileges cluster;
    private final IndexPrivileges index;
    private final Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier;

    public SubjectBasedActionPrivileges(
        RoleV7 role,
        FlattenedActionGroups actionGroups,
        Supplier<Map<String, IndexAbstraction>> indexMetadataSupplier
    ) {
        this.cluster = new ClusterPrivileges(role, actionGroups, WellKnownActions.CLUSTER_ACTIONS);
        this.index = new IndexPrivileges(
            role,
            actionGroups,
            WellKnownActions.INDEX_ACTIONS,
            WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS
        );
        this.indexMetadataSupplier = indexMetadataSupplier;
    }

    @Override
    public PrivilegesEvaluatorResponse hasClusterPrivilege(PrivilegesEvaluationContext context, String action) {
        return cluster.providesPrivilege(context, action);
    }

    @Override
    public PrivilegesEvaluatorResponse hasAnyClusterPrivilege(PrivilegesEvaluationContext context, Set<String> actions) {
        return cluster.providesAnyPrivilege(context, actions);
    }

    @Override
    public PrivilegesEvaluatorResponse hasExplicitClusterPrivilege(PrivilegesEvaluationContext context, String action) {
        return cluster.providesExplicitPrivilege(context, action);
    }

    @Override
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

        CheckTable<String, String> checkTable = CheckTable.create(
            resolvedIndices.getAllIndicesResolved(context.getClusterStateSupplier(), context.getIndexNameExpressionResolver()),
            actions
        );
        Map<String, IndexAbstraction> indexMetadata = this.indexMetadataSupplier.get();

        return this.index.providesPrivilege(context, actions, resolvedIndices, checkTable, indexMetadata);
    }

    @Override
    public PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        IndexResolverReplacer.Resolved resolvedIndices
    ) {
        CheckTable<String, String> checkTable = CheckTable.create(resolvedIndices.getAllIndices(), actions);
        return this.index.providesExplicitPrivilege(context, actions, resolvedIndices, checkTable, this.indexMetadataSupplier.get());
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
        private final ImmutableSet<String> grantedActions;

        /**
         * This contains all role names that provide wildcard (*) privileges for cluster actions.
         * This avoids a blow-up of the actionToRoles object by such roles.
         */
        private final boolean hasWildcardPermission;

        /**
         * This maps role names to a matcher which matches the action names this role provides privileges for.
         * This is only used as a last resort if the test with actionToRole and rolesWithWildcardPermissions failed.
         * This is only necessary for actions which are not contained in the list of "well-known" actions provided
         * during construction.
         *
         * This does not include privileges obtained via "*" action patterns. This is both meant as a
         * optimization and to support explicit privileges.
         */
        private final WildcardMatcher grantedActionMatcher;

        private final ImmutableSet<String> wellKnownClusterActions;

        /**
         * Creates pre-computed cluster privileges based on the given parameters.
         * <p>
         * This constructor will not throw an exception if it encounters any invalid configuration (that is,
         * in particular, unparseable regular expressions). Rather, it will just log an error. This is okay, as it
         * just results in fewer available privileges. However, having a proper error reporting mechanism would be
         * kind of nice.
         */
        ClusterPrivileges(RoleV7 role, FlattenedActionGroups actionGroups, ImmutableSet<String> wellKnownClusterActions) {
            Set<String> grantedActions = new HashSet<>();
            boolean hasWildcardPermission = false;
            List<WildcardMatcher> wildcardMatchers = new ArrayList<>();

            ImmutableSet<String> permissionPatterns = actionGroups.resolve(role.getCluster_permissions());

            for (String permission : permissionPatterns) {
                // If we have a permission which does not use any pattern, we just simply add it to the
                // "actionToRoles" map.
                // Otherwise, we match the pattern against the provided well-known cluster actions and add
                // these to the "actionToRoles" map. Additionally, for the case that the well-known cluster
                // actions are not complete, we also collect the matcher to be used as a last resort later.

                if (WildcardMatcher.isExact(permission)) {
                    grantedActions.add(permission);
                } else if (permission.equals("*")) {
                    // Special case: Roles with a wildcard "*" giving privileges for all actions. We will not resolve
                    // this stuff, but just note separately that this role just gets all the cluster privileges.
                    hasWildcardPermission = true;
                } else {
                    WildcardMatcher wildcardMatcher = WildcardMatcher.from(permission);
                    Set<String> matchedActions = wildcardMatcher.getMatchAny(wellKnownClusterActions, Collectors.toUnmodifiableSet());
                    grantedActions.addAll(matchedActions);
                    wildcardMatchers.add(wildcardMatcher);
                }
            }

            this.grantedActions = ImmutableSet.copyOf(grantedActions);
            this.hasWildcardPermission = hasWildcardPermission;
            this.grantedActionMatcher = WildcardMatcher.from(wildcardMatchers);
            this.wellKnownClusterActions = wellKnownClusterActions;
        }

        /**
         * Checks whether this instance provides privileges for the combination of the provided action and the
         * provided roles. Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
         * Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
         */
        PrivilegesEvaluatorResponse providesPrivilege(PrivilegesEvaluationContext context, String action) {

            // 1: Check roles with wildcards
            if (this.hasWildcardPermission) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Check well-known actions - this should cover most cases
            if (this.grantedActions.contains(action)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 3: Only if everything else fails: Check the matchers in case we have a non-well-known action
            if (!this.wellKnownClusterActions.contains(action)) {
                if (this.grantedActionMatcher.test(action)) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }

            return PrivilegesEvaluatorResponse.insufficient(action);
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
        PrivilegesEvaluatorResponse providesExplicitPrivilege(PrivilegesEvaluationContext context, String action) {

            // 1: Check well-known actions - this should cover most cases
            if (this.grantedActions.contains(action)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Only if everything else fails: Check the matchers in case we have a non-well-known action
            if (!this.wellKnownClusterActions.contains(action)) {
                if (this.grantedActionMatcher.test(action)) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }

            return PrivilegesEvaluatorResponse.insufficient(action);
        }

        /**
         * Checks whether this instance provides privileges for the combination of any of the provided actions and the
         * provided roles. Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
         * Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
         */
        PrivilegesEvaluatorResponse providesAnyPrivilege(PrivilegesEvaluationContext context, Set<String> actions) {

            // 1: Check roles with wildcards
            if (this.hasWildcardPermission) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Check well-known actions - this should cover most cases
            for (String action : actions) {
                if (this.grantedActions.contains(action)) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }

            // 3: Only if everything else fails: Check the matchers in case we have a non-well-known action
            for (String action : actions) {
                if (!this.wellKnownClusterActions.contains(action)) {
                    if (this.grantedActionMatcher.test(action)) {
                        return PrivilegesEvaluatorResponse.ok();
                    }
                }
            }

            if (actions.size() == 1) {
                return PrivilegesEvaluatorResponse.insufficient(actions.iterator().next());
            } else {
                return PrivilegesEvaluatorResponse.insufficient("any of " + actions);
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
        private final ImmutableMap<String, IndexPattern> actionToIndexPattern;

        /**
         * Maps role names to action names matchers to IndexPattern objects which define the indices the privileges apply to.
         * This is especially for "non-well-known" actions.
         */
        private final ImmutableMap<WildcardMatcher, IndexPattern> actionPatternToIndexPattern;

        /**
         * Maps action names to the roles which provide wildcard ("*") index privileges for the respective action.
         * This allows to answer the question "given an action and a set of roles, do I have wildcard index privileges"
         * in O(1)
         */
        private final ImmutableSet<String> actionsWithWildcardIndexPrivileges;

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
        private final ImmutableMap<String, IndexPattern> explicitActionToIndexPattern;

        /**
         * Creates pre-computed index privileges based on the given parameters.
         * <p>
         * This constructor will not throw an exception if it encounters any invalid configuration (that is,
         * in particular, unparseable regular expressions). Rather, it will just log an error. This is okay, as it
         * just results in fewer available privileges. However, having a proper error reporting mechanism would be
         * kind of nice.
         */
        IndexPrivileges(
            RoleV7 role,
            FlattenedActionGroups actionGroups,
            ImmutableSet<String> wellKnownIndexActions,
            ImmutableSet<String> explicitlyRequiredIndexActions
        ) {

            Map<String, IndexPattern.Builder> actionToIndexPattern = new HashMap<>();
            Map<WildcardMatcher, IndexPattern.Builder> actionPatternToIndexPattern = new HashMap<>();
            Set<String> actionWithWildcardIndexPrivileges = new HashSet<>();
            Map<String, IndexPattern.Builder> explicitActionToIndexPattern = new HashMap<>();

            for (RoleV7.Index indexPermissions : role.getIndex_permissions()) {
                ImmutableSet<String> permissions = actionGroups.resolve(indexPermissions.getAllowed_actions());

                for (String permission : permissions) {
                    // If we have a permission which does not use any pattern, we just simply add it to the
                    // "actionToIndexPattern" map.
                    // Otherwise, we match the pattern against the provided well-known index actions and add
                    // these to the "actionToIndexPattern" map. Additionally, for the case that the
                    // well-known index actions are not complete, we also collect the actionMatcher to be used
                    // as a last resort later.

                    if (WildcardMatcher.isExact(permission)) {
                        actionToIndexPattern.computeIfAbsent(permission, k -> new IndexPattern.Builder())
                            .add(indexPermissions.getIndex_patterns());

                        if (explicitlyRequiredIndexActions.contains(permission)) {
                            explicitActionToIndexPattern.computeIfAbsent(permission, k -> new IndexPattern.Builder())
                                .add(indexPermissions.getIndex_patterns());
                        }

                        if (indexPermissions.getIndex_patterns().contains("*")) {
                            actionWithWildcardIndexPrivileges.add(permission);
                        }
                    } else {
                        WildcardMatcher actionMatcher = WildcardMatcher.from(permission);

                        for (String action : actionMatcher.iterateMatching(wellKnownIndexActions)) {
                            actionToIndexPattern.computeIfAbsent(action, k -> new IndexPattern.Builder())
                                .add(indexPermissions.getIndex_patterns());

                            if (indexPermissions.getIndex_patterns().contains("*")) {
                                actionWithWildcardIndexPrivileges.add(permission);
                            }
                        }

                        actionPatternToIndexPattern.computeIfAbsent(actionMatcher, k -> new IndexPattern.Builder())
                            .add(indexPermissions.getIndex_patterns());

                        if (actionMatcher != WildcardMatcher.ANY) {
                            for (String action : actionMatcher.iterateMatching(explicitlyRequiredIndexActions)) {
                                explicitActionToIndexPattern.computeIfAbsent(action, k -> new IndexPattern.Builder())
                                    .add(indexPermissions.getIndex_patterns());
                            }
                        }
                    }
                }
            }

            this.actionToIndexPattern = actionToIndexPattern.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry -> entry.getValue().build()));

            this.actionPatternToIndexPattern = actionPatternToIndexPattern.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry -> entry.getValue().build()));

            this.actionsWithWildcardIndexPrivileges = ImmutableSet.copyOf(actionWithWildcardIndexPrivileges);

            this.explicitActionToIndexPattern = explicitActionToIndexPattern.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, entry -> entry.getValue().build()));

            this.wellKnownIndexActions = wellKnownIndexActions;
            this.explicitlyRequiredIndexActions = explicitlyRequiredIndexActions;
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
        PrivilegesEvaluatorResponse providesPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            IndexResolverReplacer.Resolved resolvedIndices,
            CheckTable<String, String> checkTable,
            Map<String, IndexAbstraction> indexMetadata
        ) {
            List<PrivilegesEvaluationException> exceptions = new ArrayList<>();

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
                            log.error("Error while evaluating index pattern of {}. Ignoring entry", this, e);
                            exceptions.add(new PrivilegesEvaluationException("Error while evaluating " + this, e));
                        }
                    }
                }
            }

            // If all actions are well-known, the index.rolesToActionToIndexPattern data structure that was evaluated above,
            // would have contained all the actions if privileges are provided. If there are non-well-known actions among the
            // actions, we also have to evaluate action patterns to check the authorization

            boolean allActionsWellKnown = this.wellKnownIndexActions.containsAll(actions);

            if (!checkTable.isComplete() && !allActionsWellKnown) {

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
                                        break;
                                    }
                                } catch (PrivilegesEvaluationException e) {
                                    // We can ignore these errors, as this max leads to fewer privileges than available
                                    log.error("Error while evaluating index pattern of role {}. Ignoring entry", this, e);
                                    exceptions.add(new PrivilegesEvaluationException("Error while evaluating " + this, e));
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
                return PrivilegesEvaluatorResponse.partiallyOk(availableIndices, checkTable).evaluationExceptions(exceptions);
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable)
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

            for (String action : actions) {
                if (!this.actionsWithWildcardIndexPrivileges.contains(action)) {
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
                return PrivilegesEvaluatorResponse.insufficient(CheckTable.create(ImmutableSet.of("_"), actions));
            }

            for (String action : actions) {
                IndexPattern indexPattern = this.explicitActionToIndexPattern.get(action);

                if (indexPattern != null) {
                    for (String index : checkTable.iterateUncheckedRows(action)) {
                        try {
                            if (indexPattern.matches(index, context, indexMetadata) && checkTable.check(index, action)) {
                                return PrivilegesEvaluatorResponse.ok();
                            }
                        } catch (PrivilegesEvaluationException e) {
                            // We can ignore these errors, as this max leads to fewer privileges than available
                            log.error("Error while evaluating index pattern of {}. Ignoring entry", this, e);
                            exceptions.add(new PrivilegesEvaluationException("Error while evaluating " + this, e));
                        }
                    }
                }
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable)
                .reason("No explicit privileges have been provided for the referenced indices.")
                .evaluationExceptions(exceptions);
        }
    }

}
