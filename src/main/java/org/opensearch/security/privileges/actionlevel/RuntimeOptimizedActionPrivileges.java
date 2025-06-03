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

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.IndexPattern;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.collections.CheckTable;

import static org.opensearch.security.privileges.actionlevel.WellKnownActions.isWellKnownClusterAction;
import static org.opensearch.security.privileges.actionlevel.WellKnownActions.isWellKnownIndexAction;

/**
 * This is a common base class for ActionPrivileges implementations that implement a certain
 * runtime optimization pattern:
 * <ul>
 *     <li>First check for universal wildcard privileges (very fast)</li>
 *     <li>Then check for well known actions (very fast)</li>
 *     <li>Then do pattern matching (not so fast)</li>
 * </ul>
 */
public abstract class RuntimeOptimizedActionPrivileges implements ActionPrivileges {
    private static final Logger log = LogManager.getLogger(RuntimeOptimizedActionPrivileges.class);

    protected final ClusterPrivileges cluster;
    protected final StaticIndexPrivileges index;

    RuntimeOptimizedActionPrivileges(ClusterPrivileges cluster, StaticIndexPrivileges index) {
        this.cluster = cluster;
        this.index = index;
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
    @Override
    public PrivilegesEvaluatorResponse hasIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        IndexResolverReplacer.Resolved resolvedIndices
    ) {
        PrivilegesEvaluatorResponse response = this.index.checkWildcardIndexPrivilegesOnWellKnownActions(context, actions);
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

        StatefulIndexPrivileges statefulIndex = this.currentStatefulIndexPrivileges();
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

        return this.index.providesPrivilege(context, actions, resolvedIndices, checkTable);
    }

    /**
     * Checks whether this instance provides explicit privileges for the combination of the provided action,
     * the provided indices and the provided roles.
     * <p>
     * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
     * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
     */
    @Override
    public PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        IndexResolverReplacer.Resolved resolvedIndices
    ) {
        if (!CollectionUtils.containsAny(actions, WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS)) {
            return PrivilegesEvaluatorResponse.insufficient(CheckTable.create(ImmutableSet.of("_"), actions));
        }

        CheckTable<String, String> checkTable = CheckTable.create(resolvedIndices.getAllIndices(), actions);
        return this.index.providesExplicitPrivilege(context, actions, checkTable);
    }

    /**
     * Returns the current stateful index privileges that can be used for privilege evaluation. Implementations
     * can choose to return null here; then, a slower evaluation path will be used.
     */
    protected abstract StatefulIndexPrivileges currentStatefulIndexPrivileges();

    /**
     * Base class for evaluating cluster privileges.
     */
    protected abstract static class ClusterPrivileges {
        /**
         * Checks whether this instance provides privileges for the combination of the provided action and the
         * provided roles. Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
         * Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
         */
        PrivilegesEvaluatorResponse providesPrivilege(PrivilegesEvaluationContext context, String action) {
            // 1: Check roles with wildcards
            if (checkWildcardPrivilege(context)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Check well-known actions - this should cover most cases
            if (checkPrivilegeForWellKnownAction(context, action)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 3: Only if everything else fails: Check the matchers in case we have a non-well-known action
            if (!isWellKnownClusterAction(action) && checkPrivilegeViaActionMatcher(context, action)) {
                return PrivilegesEvaluatorResponse.ok();
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
            if (checkPrivilegeForWellKnownAction(context, action)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Only if everything else fails: Check the matchers in case we have a non-well-known action
            if (!isWellKnownClusterAction(action) && checkPrivilegeViaActionMatcher(context, action)) {
                return PrivilegesEvaluatorResponse.ok();
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
            if (checkWildcardPrivilege(context)) {
                return PrivilegesEvaluatorResponse.ok();
            }

            // 2: Check well-known actions - this should cover most cases
            for (String action : actions) {
                if (checkPrivilegeForWellKnownAction(context, action)) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }

            // 3: Only if everything else fails: Check the matchers in case we have a non-well-known action
            for (String action : actions) {
                if (!isWellKnownClusterAction(action) && checkPrivilegeViaActionMatcher(context, action)) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }

            if (actions.size() == 1) {
                return PrivilegesEvaluatorResponse.insufficient(actions.iterator().next());
            } else {
                return PrivilegesEvaluatorResponse.insufficient("any of " + actions);
            }
        }

        /**
         * Tests whether the current user (according to the context data) has wildcard cluster privileges.
         * <p>
         * Implementations of this class may interpret the context data differently; they can check the mapped roles
         * or just the subject.
         */
        protected abstract boolean checkWildcardPrivilege(PrivilegesEvaluationContext context);

        /**
         * Tests whether the current user (according to the context data) has privileges for the given well known cluster action.
         * Returns false if no privileges are given or if the given action is not a well known action.
         * <p>
         * Implementations of this class may interpret the context data differently; they can check the mapped roles
         * or just the subject.
         */
        protected abstract boolean checkPrivilegeForWellKnownAction(PrivilegesEvaluationContext context, String action);

        /**
         * Tests whether a privilege is provided via a pattern on an action (like "indices:data/read/*").
         * This does NOT include the full wildcard pattern "*".
         * <p>
         * This is the slowest way to check for a privilege.
         */
        protected abstract boolean checkPrivilegeViaActionMatcher(PrivilegesEvaluationContext context, String action);

    }

    /**
     * Base class for evaluating index permissions which evaluates index patterns at privilege evaluation time.
     */
    protected abstract static class StaticIndexPrivileges {

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
        protected abstract PrivilegesEvaluatorResponse providesPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            IndexResolverReplacer.Resolved resolvedIndices,
            CheckTable<String, String> checkTable
        );

        /**
         * Checks whether this instance provides explicit privileges for the combination of the provided action,
         * the provided indices and the provided roles.
         * <p>
         * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
         * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
         */
        protected abstract PrivilegesEvaluatorResponse providesExplicitPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable
        );

        /**
         * Tests whether the current user (according to the context data) has wildcard index privileges for the given well known index actions.
         * Returns false if no privileges are given or if the given actions are not well known actions.
         * <p>
         * Implementations of this class may interpret the context data differently; they can check the mapped roles
         * or just the subject.
         */
        protected abstract PrivilegesEvaluatorResponse checkWildcardIndexPrivilegesOnWellKnownActions(
            PrivilegesEvaluationContext context,
            Set<String> actions
        );

        /**
         * Tests whether the current user (according to the context data) has index privileges for the given well known
         * index actions via index patterns.
         * <p>
         * This method has two side-effects which transport the result of this check:
         * <ul>
         *     <li>The action/index combinations for which privileges are found are checked in the given check table.
         *     <li>In case of any PrivilegeEvaluationException, it is added to the given list
         * </ul>
         */
        protected void checkPrivilegeWithIndexPatternOnWellKnownActions(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable,
            ImmutableMap<String, IndexPattern> actionToIndexPattern,
            List<PrivilegesEvaluationException> exceptions
        ) {
            Map<String, IndexAbstraction> indexMetadata = context.getIndicesLookup();

            for (String action : actions) {
                IndexPattern indexPattern = actionToIndexPattern.get(action);

                if (indexPattern != null) {
                    for (String index : checkTable.iterateUncheckedRows(action)) {
                        try {
                            if (indexPattern.matches(index, context, indexMetadata) && checkTable.check(index, action)) {
                                return;
                            }
                        } catch (PrivilegesEvaluationException e) {
                            // We can ignore these errors, as this max leads to fewer privileges than available
                            log.error("Error while evaluating index pattern of {}. Ignoring entry", this, e);
                            exceptions.add(new PrivilegesEvaluationException("Error while evaluating " + this, e));
                        }
                    }
                }
            }
        }

        /**
         * Does a privilege check for non-well known actions. This is the slowest method and should be used last.
         * <p>
         * This method has two side-effects which transport the result of this check:
         * <ul>
         *     <li>The action/index combinations for which privileges are found are checked in the given check table.
         *     <li>In case of any PrivilegeEvaluationException, it is added to the given list
         * </ul>
         */
        protected void checkPrivilegesForNonWellKnownActions(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable,
            ImmutableMap<WildcardMatcher, IndexPattern> actionPatternToIndexPattern,
            List<PrivilegesEvaluationException> exceptions
        ) {
            Map<String, IndexAbstraction> indexMetadata = context.getIndicesLookup();

            for (String action : actions) {
                if (isWellKnownIndexAction(action)) {
                    continue;
                }

                for (Map.Entry<WildcardMatcher, IndexPattern> entry : actionPatternToIndexPattern.entrySet()) {
                    WildcardMatcher actionMatcher = entry.getKey();
                    IndexPattern indexPattern = entry.getValue();

                    if (actionMatcher.test(action)) {
                        for (String index : checkTable.iterateUncheckedRows(action)) {
                            try {
                                if (indexPattern.matches(index, context, indexMetadata) && checkTable.check(index, action)) {
                                    return;
                                }
                            } catch (PrivilegesEvaluationException e) {
                                // We can ignore these errors, as this max leads to fewer privileges than available
                                log.error("Error while evaluating index pattern {}. Ignoring entry", indexPattern, e);
                                exceptions.add(
                                    new PrivilegesEvaluationException("Error while evaluating index pattern " + indexPattern, e)
                                );
                            }
                        }
                    }
                }
            }
        }

        /**
         * Creates a PrivilegesEvaluationResponse in the case we find that the user does not have full privileges.
         * This result is built based on the state of the given check table:
         * <ul>
         *     <li>If the check table is empty, a result with the state "insufficient" will be returned</li>
         *     <li>If the check table is not empty, a result with the state "partially ok" will be returned. The response
         *     object will carry a list of the indices for which we have privileges. This can be used for the DNFOF mode.</li>
         * </ul>
         */
        protected PrivilegesEvaluatorResponse responseForIncompletePrivileges(
            PrivilegesEvaluationContext context,
            IndexResolverReplacer.Resolved resolvedIndices,
            CheckTable<String, String> checkTable,
            List<PrivilegesEvaluationException> exceptions
        ) {
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
    }

    /**
     * Base class for evaluating index permissions which evaluates index patterns ahead of the time using the current
     * cluster state.
     */
    protected abstract static class StatefulIndexPrivileges {

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
        protected abstract PrivilegesEvaluatorResponse providesPrivilege(
            Set<String> actions,
            IndexResolverReplacer.Resolved resolvedIndices,
            PrivilegesEvaluationContext context,
            CheckTable<String, String> checkTable
        );
    }

}
