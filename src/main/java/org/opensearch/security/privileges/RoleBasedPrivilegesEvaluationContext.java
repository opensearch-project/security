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

import java.util.function.Supplier;

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.ActionRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

/**
 * Request-scoped context information for privilege evaluation.
 * <p>
 * This class carries metadata about the request and provides caching facilities for data which might need to be
 * evaluated several times per request.
 * <p>
 * As this class is request-scoped, it is only used by a single thread. Thus, no thread synchronization mechanisms
 * are necessary.
 */
public class RoleBasedPrivilegesEvaluationContext extends PrivilegesEvaluationContext {
    private ImmutableSet<String> mappedRoles;

    public RoleBasedPrivilegesEvaluationContext(
        User user,
        ImmutableSet<String> mappedRoles,
        String action,
        ActionRequest request,
        Task task,
        IndexResolverReplacer indexResolverReplacer,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<ClusterState> clusterStateSupplier
    ) {
        super(user, action, request, task, indexResolverReplacer, indexNameExpressionResolver, clusterStateSupplier);
        this.mappedRoles = mappedRoles;
    }

    @Override
    public ImmutableSet<String> getMappedRoles() {
        return mappedRoles;
    }

    /**
     * Note: Ideally, mappedRoles would be an unmodifiable attribute. PrivilegesEvaluator however contains logic
     * related to OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION which first validates roles and afterwards modifies
     * them again. Thus, we need to be able to set this attribute.
     *
     * However, this method should be only used for this one particular phase. Normally, all roles should be determined
     * upfront and stay constant during the whole privilege evaluation process.
     */
    @Override
    void setMappedRoles(ImmutableSet<String> mappedRoles) {
        this.mappedRoles = mappedRoles;
    }

    @Override
    public String toString() {
        return "RoleBasedPrivilegesEvaluationContext{"
            + "user="
            + getUser()
            + ", action='"
            + getAction()
            + '\''
            + ", request="
            + getRequest()
            + ", resolvedRequest="
            + getResolvedRequest()
            + ", mappedRoles="
            + mappedRoles
            + '}';
    }
}
