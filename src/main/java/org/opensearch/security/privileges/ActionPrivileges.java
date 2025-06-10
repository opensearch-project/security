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

import java.util.Set;

import org.opensearch.cluster.metadata.ResolvedIndices;

/**
 * Defines the general interface for evaluating privileges on actions. References to ActionPrivileges instances
 * should be usually obtained by PrivilegesEvaluator.createContext().getActionPrivileges().
 * <p>
 * Different ActionPrivileges implementations might consider different data from the PrivilegeEvaluationContext
 * for privilege evaluation. Some (like RoleBasedActionPrivileges) might consider the mapped roles. Others might
 * be completely self-sufficient because the PrivilegesEvaluator.createContext() method already checked all
 * pre-conditions to choose the correct instance (e.g. for plugins or API tokens).
 */
public interface ActionPrivileges {

    /**
     * Checks whether this instance provides privileges for the provided action.
     *
     * @param context The context of the privilege evaluation. Depending on the ActionPrivileges implementation,
     *                the mapped role from the context might be used (RoleBasedActionPrivileges) or not.
     * @param action The name of the OpenSearch action to be evaluated.
     * @return Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
     *    Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
     */
    PrivilegesEvaluatorResponse hasClusterPrivilege(PrivilegesEvaluationContext context, String action);

    /**
     * Checks whether this instance provides privileges for any of the provided actions.
     *
     * @param context The context of the privilege evaluation. Depending on the ActionPrivileges implementation,
     *                the mapped role from the context might be used (RoleBasedActionPrivileges) or not.
     * @param actions The names of the OpenSearch action to be evaluated.
     * @return Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
     *    Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
     */

    PrivilegesEvaluatorResponse hasAnyClusterPrivilege(PrivilegesEvaluationContext context, Set<String> actions);

    /**
     * Checks whether this instance provides explicit privileges for the combination of the provided action and the
     * provided context.
     * <p>
     * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
     * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
     *
     * @param context The context of the privilege evaluation. Depending on the ActionPrivileges implementation,
     *                the mapped role from the context might be used (RoleBasedActionPrivileges) or not.
     * @param action The name of the OpenSearch action to be evaluated.
     * @return Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
     *    Otherwise, allowed will be false and missingPrivileges will contain the name of the given action.
     */
    PrivilegesEvaluatorResponse hasExplicitClusterPrivilege(PrivilegesEvaluationContext context, String action);

    /**
     * Checks whether this instance provides privileges for the combination of the provided action,
     * the provided indices and the provided context.
     * <p>
     * Returns a PrivilegesEvaluatorResponse with allowed=true if privileges are available.
     * <p>
     * If privileges are only available for a sub-set of indices, isPartiallyOk() will return true
     * and the indices for which privileges are available are returned by getAvailableIndices(). This allows the
     * do_not_fail_on_forbidden behaviour.
     */
    PrivilegesEvaluatorResponse hasIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        ResolvedIndices resolvedIndices
    );

    /**
     * Checks whether this instance provides explicit privileges for the combination of the provided action,
     * the provided indices and the provided roles.
     * <p>
     * Explicit means here that the privilege is not granted via a "*" action privilege wildcard. Other patterns
     * are possible. See also: https://github.com/opensearch-project/security/pull/2411 and https://github.com/opensearch-project/security/issues/3038
     */
    PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(
        PrivilegesEvaluationContext context,
        Set<String> actions,
        ResolvedIndices resolvedIndices
    );

    ActionPrivileges EMPTY = new ActionPrivileges() {
        @Override
        public PrivilegesEvaluatorResponse hasClusterPrivilege(PrivilegesEvaluationContext context, String action) {
            return PrivilegesEvaluatorResponse.insufficient(action).reason("User has no privileges");
        }

        @Override
        public PrivilegesEvaluatorResponse hasAnyClusterPrivilege(PrivilegesEvaluationContext context, Set<String> actions) {
            return PrivilegesEvaluatorResponse.insufficient("any of " + actions).reason("User has no privileges");
        }

        @Override
        public PrivilegesEvaluatorResponse hasExplicitClusterPrivilege(PrivilegesEvaluationContext context, String action) {
            return PrivilegesEvaluatorResponse.insufficient(action).reason("User has no privileges");
        }

        @Override
        public PrivilegesEvaluatorResponse hasIndexPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            ResolvedIndices resolvedIndices
        ) {
            return PrivilegesEvaluatorResponse.insufficient("all of " + actions).reason("User has no privileges");
        }

        @Override
        public PrivilegesEvaluatorResponse hasExplicitIndexPrivilege(
            PrivilegesEvaluationContext context,
            Set<String> actions,
            ResolvedIndices resolvedIndices
        ) {
            return PrivilegesEvaluatorResponse.insufficient("all of " + actions).reason("User has no privileges");
        }
    };
}
