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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.IndexPattern;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.support.ConfigConstants;
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
        OptionallyResolvedIndices resolvedIndices
    ) {
        if (resolvedIndices.local().isEmpty()) {
            // This is necessary for requests which operate on remote indices.
            // Access control for the remote indices will be performed on the remote cluster.
            log.debug("No local indices; grant the request");
            return PrivilegesEvaluatorResponse.ok();
        }

        // TODO one might want to consider to create a semantic wrapper for action in order to be better tell apart
        // what's the action and what's the index in the generic parameters of CheckTable.
        CheckTable<String, String> checkTable = CheckTable.create(resolvedIndices.local().names(context.clusterState()), actions);

        IntermediateResult result = this.index.checkWildcardIndexPrivilegesOnWellKnownActions(context, actions, checkTable);
        if (result != null) {
            return this.index.finalizeResult(context, result);
        }

        StatefulIndexPrivileges statefulIndex = this.currentStatefulIndexPrivileges();

        if (statefulIndex != null) {
            IntermediateResult resultFromStatefulIndex = statefulIndex.providesPrivilege(actions, context, checkTable);

            if (resultFromStatefulIndex != null) {
                // If we get a result from statefulIndex, we are done.
                return this.index.finalizeResult(context, resultFromStatefulIndex);
            }

            // Otherwise, we need to carry on checking privileges using the non-stateful object.
            // Note: statefulIndex.hasPermission() modifies as a side effect the checkTable.
            // We can carry on using this as an intermediate result and further complete checkTable below.
        }

        IntermediateResult resultFromStaticIndex = this.index.providesPrivilege(context, actions, checkTable);
        return this.index.finalizeResult(context, resultFromStaticIndex);
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
        OptionallyResolvedIndices resolvedIndices
    ) {
        if (!CollectionUtils.containsAny(actions, WellKnownActions.EXPLICITLY_REQUIRED_INDEX_ACTIONS)) {
            return PrivilegesEvaluatorResponse.insufficient(CheckTable.create(ImmutableSet.of("_"), actions));
        }

        CheckTable<String, String> checkTable = CheckTable.create(resolvedIndices.local().names(context.clusterState()), actions);
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
        protected final Predicate<String> universallyDeniedIndices;
        protected final Predicate<String> indicesNeedingSystemIndexPrivileges;

        protected StaticIndexPrivileges(SpecialIndexProtection specialIndexProtection) {
            this.universallyDeniedIndices = specialIndexProtection.universallyDeniedIndices;
            this.indicesNeedingSystemIndexPrivileges = specialIndexProtection.indicesNeedingSystemIndexPrivileges;
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
        protected abstract IntermediateResult providesPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
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

        protected abstract boolean providesExplicitPrivilege(
            PrivilegesEvaluationContext context,
            String index,
            String action,
            List<PrivilegesEvaluationException> exceptions
        );

        /**
         * Tests whether the current user (according to the context data) has wildcard index privileges for the given well known index actions.
         * Returns false if no privileges are given or if the given actions are not well known actions.
         * <p>
         * Implementations of this class may interpret the context data differently; they can check the mapped roles
         * or just the subject.
         */
        protected abstract IntermediateResult checkWildcardIndexPrivilegesOnWellKnownActions(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            CheckTable<String, String> checkTable
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
         * When we have finished the "normal" privilege evaluation, which is based on index_permissions in roles.yml,
         * we have to pass the CheckTable with the available privileges through this method in order to have specially
         * protected indices and actions removed again from the CheckTable.
         */
        protected PrivilegesEvaluatorResponse finalizeResult(PrivilegesEvaluationContext context, IntermediateResult intermediateResult) {
            CheckTable<String, String> checkTable = intermediateResult.indexToActionCheckTable;
            List<PrivilegesEvaluationException> exceptions = new ArrayList<>(intermediateResult.exceptions);
            if (this.universallyDeniedIndices != null) {
                checkTable.uncheckIf(this.universallyDeniedIndices, checkTable.getColumns());
            }
            if (this.indicesNeedingSystemIndexPrivileges != null) {
                checkTable.uncheckIf(index -> this.isUnauthorizedSystemIndex(context, index, exceptions), checkTable.getColumns());
            }

            if (checkTable.isComplete()) {
                return PrivilegesEvaluatorResponse.ok();
            }

            Set<String> availableIndices = checkTable.getCompleteRows();

            if (!availableIndices.isEmpty()) {
                return PrivilegesEvaluatorResponse.partiallyOk(availableIndices, checkTable).evaluationExceptions(exceptions);
            }

            Set<String> allIndices = checkTable.getRows();

            String reason;
            if (allIndices.size() != 1) {
                reason = "None of the referenced indices has sufficient permissions";
            } else {
                reason = "Insufficient permissions for the referenced index";
            }

            return PrivilegesEvaluatorResponse.insufficient(checkTable).reason(reason).evaluationExceptions(exceptions);

        }

        /**
         * Returns true if the given indexOrAlias is a system index or an alias containing a system index AND if
         * the current user does not have the necessary explicit privilege to access this system index.
         */
        private boolean isUnauthorizedSystemIndex(
            PrivilegesEvaluationContext context,
            String indexOrAlias,
            List<PrivilegesEvaluationException> exceptions
        ) {
            if (this.indicesNeedingSystemIndexPrivileges.test(indexOrAlias)) {
                return !providesExplicitPrivilege(context, indexOrAlias, ConfigConstants.SYSTEM_INDEX_PERMISSION, exceptions);
            }

            IndexAbstraction indexAbstraction = context.getIndicesLookup().get(indexOrAlias);
            if (indexAbstraction instanceof IndexAbstraction.Alias alias) {
                for (IndexMetadata index : alias.getIndices()) {
                    if (this.indicesNeedingSystemIndexPrivileges.test(index.getIndex().getName())) {
                        return !providesExplicitPrivilege(
                            context,
                            index.getIndex().getName(),
                            ConfigConstants.SYSTEM_INDEX_PERMISSION,
                            exceptions
                        );
                    }
                }
            }

            return false;
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
         * @param context         context information like user, resolved roles, etc.
         * @param checkTable      An action/index matrix. This method will modify the table as a side effect and check the cells where privileges are present.
         * @return PrivilegesEvaluatorResponse.ok() or null.
         */
        protected abstract IntermediateResult providesPrivilege(
            Set<String> actions,
            PrivilegesEvaluationContext context,
            CheckTable<String, String> checkTable
        );
    }

    public static class SpecialIndexProtection {
        public static final SpecialIndexProtection NONE = new SpecialIndexProtection(null, null);

        protected final Predicate<String> universallyDeniedIndices;
        protected final Predicate<String> indicesNeedingSystemIndexPrivileges;

        public SpecialIndexProtection(Predicate<String> universallyDeniedIndices, Predicate<String> indicesNeedingSystemIndexPrivileges) {
            this.universallyDeniedIndices = universallyDeniedIndices;
            this.indicesNeedingSystemIndexPrivileges = indicesNeedingSystemIndexPrivileges;
        }
    }

    protected static class IntermediateResult {

        protected final CheckTable<String, String> indexToActionCheckTable;
        protected final String reason;
        protected final ImmutableList<PrivilegesEvaluationException> exceptions;

        protected IntermediateResult(CheckTable<String, String> indexToActionCheckTable) {
            this.indexToActionCheckTable = indexToActionCheckTable;
            this.reason = null;
            this.exceptions = ImmutableList.of();
        }

        IntermediateResult(
            CheckTable<String, String> indexToActionCheckTable,
            String reason,
            ImmutableList<PrivilegesEvaluationException> exceptions
        ) {
            this.indexToActionCheckTable = indexToActionCheckTable;
            this.reason = reason;
            this.exceptions = exceptions;
        }

        protected IntermediateResult reason(String reason) {
            return new IntermediateResult(this.indexToActionCheckTable, reason, this.exceptions);
        }

        protected IntermediateResult evaluationExceptions(List<PrivilegesEvaluationException> exceptions) {
            if (exceptions.isEmpty()) {
                return this;
            } else {
                ImmutableList.Builder<PrivilegesEvaluationException> newExceptions = ImmutableList.builder();
                newExceptions.addAll(this.exceptions);
                newExceptions.addAll(exceptions);
                return new IntermediateResult(this.indexToActionCheckTable, reason, newExceptions.build());
            }
        }
    }
}
