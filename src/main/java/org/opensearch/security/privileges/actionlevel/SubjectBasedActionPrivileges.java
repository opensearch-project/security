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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.IndexPattern;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.collections.CheckTable;

import static org.opensearch.security.privileges.actionlevel.WellKnownActions.allWellKnownIndexActions;

/**
 * An ActionPrivileges implementation that is valid only for a single entity.
 * This means that individual instances of this class must be created for individual entities. The mapped roles
 * from the context are not regarded by this class.
 * <p>
 * The method PrivilegesEvaluator.createContext() is responsible for making sure that the correct class is used.
 * <p>
 * This class is useful for plugin users and API tokens.
 */
public class SubjectBasedActionPrivileges extends RuntimeOptimizedActionPrivileges {

    public static ImmutableMap<String, ActionPrivileges> buildFromMap(
        Map<String, RoleV7> pluginIdToRolePrivileges,
        FlattenedActionGroups staticActionGroups,
        RuntimeOptimizedActionPrivileges.SpecialIndexProtection specialIndexProtection
    ) {
        Map<String, SubjectBasedActionPrivileges> result = new HashMap<>(pluginIdToRolePrivileges.size());

        for (Map.Entry<String, RoleV7> entry : pluginIdToRolePrivileges.entrySet()) {
            result.put(
                entry.getKey(),
                new SubjectBasedActionPrivileges(entry.getValue(), staticActionGroups, specialIndexProtection, false)
            );
        }

        return ImmutableMap.copyOf(result);
    }

    private static final Logger log = LogManager.getLogger(SubjectBasedActionPrivileges.class);

    /**
     * Creates a new immutable instance from the given parameters.
     *
     * @param role defines the privileges configuration. This is not a role per se, but the existing class has a
     *             suitable structure to carry the information. At one point, it might make sense to define an
     *             abstract interface.
     * @param actionGroups The FlattenedActionGroups instance that shall be used to resolve the action groups
     *                     specified in the roles configuration.
     */
    public SubjectBasedActionPrivileges(
        RoleV7 role,
        FlattenedActionGroups actionGroups,
        SpecialIndexProtection specialIndexProtection,
        boolean breakDownAliases
    ) {
        super(
            new ClusterPrivileges(actionGroups.resolve(role.getCluster_permissions())),
            new IndexPrivileges(role, actionGroups, specialIndexProtection, breakDownAliases),
            breakDownAliases
        );
    }

    /**
     * At the moment, this class does not provide StatefulIndexPrivileges.
     * Thus, always the slightly slower index matching code path will be used. For plugins, however,
     * that should be okay, as they likely request specific indices without patterns.
     */
    @Override
    protected StatefulIndexPrivileges currentStatefulIndexPrivileges() {
        return null;
    }

    /**
     * Pre-computed, optimized cluster privilege maps. Instances of this class are immutable.
     * <p>
     * The data structures in this class are optimized for answering the question
     * "I have action A. Do I have authorization to execute the action?".
     * <p>
     * The check will be possible in time O(1) for "well-known" actions when the user actually has the privileges.
     */
    static class ClusterPrivileges extends RuntimeOptimizedActionPrivileges.ClusterPrivileges {

        /**
         * A set of action names for which the subject has been granted a privilege.
         * Note that the mapping is not comprehensive, additionally the attribute providesWildcardPrivilege
         * and grantedActionMatcher need to be considered for a full view of the privileges.
         * <p>
         * This does not include privileges obtained via "*" action patterns. This is both meant as a
         * optimization and to support explicit privileges.
         */
        private final ImmutableSet<String> grantedActions;

        /**
         * This is true if the current subject was granted wildcard (*) privileges for cluster actions.
         * This avoids a blow-up of the grantedActions object by such configurations.
         */
        private final boolean providesWildcardPrivilege;

        /**
         * This WildcardMatcher matches the privileges of the current subject against action names this.
         * This is only used as a last resort if the test with grantedActions and providesWildcardPrivilege failed.
         * This is only necessary for actions which are not contained in the list of "well-known" actions provided
         * during construction.
         *
         * This does not include privileges obtained via "*" action patterns. This is both meant as a
         * optimization and to support explicit privileges.
         */
        private final WildcardMatcher grantedActionMatcher;

        /**
         * Creates pre-computed cluster privileges based on the given permission patterns.
         *
         * @param permissionPatterns a collection of strings representing WildcardMatcher patterns that can match
         *                           on action names. Any action groups must have been already resolved before these
         *                           are passed here.
         */
        ClusterPrivileges(ImmutableSet<String> permissionPatterns) {
            Set<String> grantedActions = new HashSet<>();
            boolean hasWildcardPermission = false;
            List<WildcardMatcher> wildcardMatchers = new ArrayList<>();

            for (String permission : permissionPatterns) {
                // If we have a permission which does not use any pattern, we just simply add it to the
                // "grantedActions" set.
                // Otherwise, we match the pattern against the provided well-known cluster actions and add
                // these to the "grantedActions" set. Additionally, for the case that the well-known cluster
                // actions are not complete, we also collect the matcher to be used as a last resort later.

                if (WildcardMatcher.isExact(permission)) {
                    grantedActions.add(permission);
                } else if (permission.equals("*")) {
                    // Special case: Configurations with a wildcard "*" giving privileges for all actions. We will not resolve
                    // this stuff, but just note separately that this subject just gets all the cluster privileges.
                    hasWildcardPermission = true;
                } else {
                    WildcardMatcher wildcardMatcher = WildcardMatcher.from(permission);
                    Set<String> matchedActions = wildcardMatcher.getMatchAny(
                        WellKnownActions.CLUSTER_ACTIONS,
                        Collectors.toUnmodifiableSet()
                    );
                    grantedActions.addAll(matchedActions);
                    wildcardMatchers.add(wildcardMatcher);
                }
            }

            this.grantedActions = ImmutableSet.copyOf(grantedActions);
            this.providesWildcardPrivilege = hasWildcardPermission;
            this.grantedActionMatcher = WildcardMatcher.from(wildcardMatchers);
        }

        @Override
        protected boolean checkWildcardPrivilege(PrivilegesEvaluationContext context) {
            return this.providesWildcardPrivilege;
        }

        @Override
        protected boolean checkPrivilegeForWellKnownAction(PrivilegesEvaluationContext context, String action) {
            return this.grantedActions.contains(action);
        }

        @Override
        protected boolean checkPrivilegeViaActionMatcher(PrivilegesEvaluationContext context, String action) {
            return this.grantedActionMatcher.test(action);
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
     * 1. Answer the question "given an action, do I have wildcard index privileges" in O(1)
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
         * Maps concrete action names to IndexPattern objects which define the indices the privileges apply to.
         */
        private final ImmutableMap<String, IndexPattern> actionToIndexPattern;

        /**
         * Maps action names matchers to IndexPattern objects which define the indices the privileges apply to.
         * This is especially for "non-well-known" actions.
         */
        private final ImmutableMap<WildcardMatcher, IndexPattern> actionPatternToIndexPattern;

        /**
         * A set of action names for which the subject has wildcard ("*") index privileges.
         * This allows to answer the question "given an action, do I have wildcard index privileges"
         * in O(1)
         */
        private final ImmutableSet<String> actionsWithWildcardIndexPrivileges;

        /**
         * Maps concrete action names to IndexPattern objects which define the indices the privileges apply to.
         * The action names are only explicitly granted privileges which are listed in explicitlyRequiredIndexActions.
         * <p>
         * Compare https://github.com/opensearch-project/security/pull/2887
         */
        private final ImmutableMap<String, IndexPattern> explicitActionToIndexPattern;

        /**
         * Creates pre-computed index privileges based on the given parameters.
         */
        IndexPrivileges(
            RoleV7 role,
            FlattenedActionGroups actionGroups,
            SpecialIndexProtection specialIndexProtection,
            boolean memberIndexPrivilegesYieldALiasPrivileges
        ) {
            super(specialIndexProtection);

            Function<Object, IndexPattern.Builder> indexPatternBuilder = k -> new IndexPattern.Builder(
                memberIndexPrivilegesYieldALiasPrivileges
            );

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
                        actionToIndexPattern.computeIfAbsent(permission, indexPatternBuilder).add(indexPermissions.getIndex_patterns());

                        if (WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS.contains(permission)) {
                            explicitActionToIndexPattern.computeIfAbsent(permission, indexPatternBuilder)
                                .add(indexPermissions.getIndex_patterns());
                        }

                        if (indexPermissions.getIndex_patterns().contains("*")) {
                            actionWithWildcardIndexPrivileges.add(permission);
                        }
                    } else {
                        WildcardMatcher actionMatcher = WildcardMatcher.from(permission);

                        for (String action : actionMatcher.iterateMatching(WellKnownActions.INDEX_ACTIONS)) {
                            actionToIndexPattern.computeIfAbsent(action, indexPatternBuilder).add(indexPermissions.getIndex_patterns());

                            if (indexPermissions.getIndex_patterns().contains("*")) {
                                actionWithWildcardIndexPrivileges.add(permission);
                            }
                        }

                        actionPatternToIndexPattern.computeIfAbsent(actionMatcher, indexPatternBuilder)
                            .add(indexPermissions.getIndex_patterns());

                        if (actionMatcher != WildcardMatcher.ANY) {
                            for (String action : actionMatcher.iterateMatching(WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS)) {
                                explicitActionToIndexPattern.computeIfAbsent(action, indexPatternBuilder)
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
        }

        /**
         * Checks whether this instance provides privileges for the combination of the provided action and
         * the provided indices.
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

            checkPrivilegeWithIndexPatternOnWellKnownActions(context, actions, checkTable, actionToIndexPattern, exceptions);
            if (checkTable.isComplete()) {
                return new IntermediateResult(checkTable).evaluationExceptions(exceptions);
            }

            // If all actions are well-known, the index.actionToIndexPattern data structure that was evaluated above,
            // would have contained all the actions if privileges are provided. If there are non-well-known actions among the
            // actions, we also have to evaluate action patterns to check the authorization

            if (!allWellKnownIndexActions(actions)) {
                checkPrivilegesForNonWellKnownActions(context, actions, checkTable, this.actionPatternToIndexPattern, exceptions);
                if (checkTable.isComplete()) {
                    return new IntermediateResult(checkTable).evaluationExceptions(exceptions);
                }
            }

            return new IntermediateResult(checkTable).evaluationExceptions(exceptions);
        }

        @Override
        protected PrivilegesEvaluatorResponse providesPrivilegeOnAnyIndex(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable
        ) {
            checkTable.checkIf(
                checkTable.getRows(),
                action -> !this.actionToIndexPattern.getOrDefault(action, IndexPattern.EMPTY).isEmpty()
            );
            if (checkTable.isComplete()) {
                return PrivilegesEvaluatorResponse.ok(checkTable);
            }

            // If all actions are well-known, the index.rolesToActionToIndexPattern data structure that was evaluated above,
            // would have contained all the actions if privileges are provided. If there are non-well-known actions among the
            // actions, we also have to evaluate action patterns to check the authorization

            if (!allWellKnownIndexActions(actions)) {
                for (String action : actions) {
                    for (Map.Entry<WildcardMatcher, IndexPattern> entry : this.actionPatternToIndexPattern.entrySet()) {
                        WildcardMatcher actionMatcher = entry.getKey();
                        IndexPattern indexPattern = entry.getValue();

                        if (actionMatcher.test(action) && !indexPattern.isEmpty()) {
                            checkTable.getRows().forEach(index -> checkTable.check(index, action));
                            if (checkTable.isComplete()) {
                                return PrivilegesEvaluatorResponse.ok(checkTable);
                            }
                        }
                    }
                }

            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable)
                .reason("The user does not have any index privileges for the requested action");
        }

        /**
         * Returns PrivilegesEvaluatorResponse.ok() if the user identified in the context object has privileges for all
         * indices (using *) for the given actions. Returns null otherwise. Then, further checks must be done to check
         * the user's privileges.
         */
        @Override
        protected IntermediateResult checkWildcardIndexPrivilegesOnWellKnownActions(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable
        ) {
            for (String action : actions) {
                if (!this.actionsWithWildcardIndexPrivileges.contains(action)) {
                    return null;
                }
            }

            return new IntermediateResult(checkTable);
        }

        /**
         * Checks whether this instance provides explicit privileges for the combination of the provided action and
         * the provided indices.
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
                            log.error("Error while evaluating {}. Ignoring entry", indexPattern, e);
                            exceptions.add(new PrivilegesEvaluationException("Error while evaluating " + indexPattern, e));
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

            IndexPattern indexPattern = this.explicitActionToIndexPattern.get(action);

            if (indexPattern != null) {
                try {
                    if (indexPattern.matches(index, context, indexMetadata)) {
                        return true;
                    }
                } catch (PrivilegesEvaluationException e) {
                    // We can ignore these errors, as this max leads to fewer privileges than available
                    log.error("Error while evaluating {}. Ignoring entry", indexPattern, e);
                    exceptions.add(new PrivilegesEvaluationException("Error while evaluating " + indexPattern, e));
                }

            }

            return false;
        }
    }

}
