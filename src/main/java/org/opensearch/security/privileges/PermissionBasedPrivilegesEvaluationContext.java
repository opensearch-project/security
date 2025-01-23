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
import org.opensearch.security.action.apitokens.Permissions;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

public class PermissionBasedPrivilegesEvaluationContext extends PrivilegesEvaluationContext {
    private final Permissions permissions;

    public PermissionBasedPrivilegesEvaluationContext(
        User user,
        String action,
        ActionRequest request,
        Task task,
        IndexResolverReplacer indexResolverReplacer,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<ClusterState> clusterStateSupplier,
        Permissions permissions
    ) {
        super(user, action, request, task, indexResolverReplacer, indexNameExpressionResolver, clusterStateSupplier);
        this.permissions = permissions;
    }

    @Override
    public String toString() {
        return "PermissionBasedPrivilegesEvaluationContext{"
            + "user="
            + getUser()
            + ", action='"
            + getAction()
            + '\''
            + ", request="
            + getRequest()
            + ", resolvedRequest="
            + getResolvedRequest()
            + ", permissions="
            + permissions
            + '}';
    }

    public Permissions getPermissions() {
        return permissions;
    }

    @Override
    public ImmutableSet<String> getMappedRoles() {
        return ImmutableSet.of();
    }

    @Override
    void setMappedRoles(ImmutableSet<String> roles) {}
}
