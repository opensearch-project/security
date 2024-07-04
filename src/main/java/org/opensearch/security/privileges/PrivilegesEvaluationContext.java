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

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.ActionRequest;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

/**
 * Request-scoped context information for privilege evaluation.
 *
 * This class carries metadata about the request and provides caching facilities for data which might need to be
 * evaluated several times per request.
 *
 * As this class is request-scoped, it is only used by a single thread. Thus, no thread synchronization mechanisms
 * are necessary.
 */
public class PrivilegesEvaluationContext {
    private final User user;
    private final String action;
    private final ActionRequest request;
    private IndexResolverReplacer.Resolved resolvedRequest;
    private final Task task;
    private ImmutableSet<String> mappedRoles;
    private final IndexResolverReplacer indexResolverReplacer;

    public PrivilegesEvaluationContext(
        User user,
        ImmutableSet<String> mappedRoles,
        String action,
        ActionRequest request,
        Task task,
        IndexResolverReplacer indexResolverReplacer
    ) {
        this.user = user;
        this.mappedRoles = mappedRoles;
        this.action = action;
        this.request = request;
        this.task = task;
        this.indexResolverReplacer = indexResolverReplacer;
    }

    public User getUser() {
        return user;
    }

    public String getAction() {
        return action;
    }

    public ActionRequest getRequest() {
        return request;
    }

    public IndexResolverReplacer.Resolved getResolvedRequest() {
        IndexResolverReplacer.Resolved result = this.resolvedRequest;

        if (result == null) {
            result = indexResolverReplacer.resolveRequest(request);
            this.resolvedRequest = result;
        }

        return result;
    }

    public Task getTask() {
        return task;
    }

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
    void setMappedRoles(ImmutableSet<String> mappedRoles) {
        this.mappedRoles = mappedRoles;
    }

}
