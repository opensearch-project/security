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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.ActionRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.WildcardMatcher;
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

    /**
     * This caches the ready to use WildcardMatcher instances for the current request. Many index patterns have
     * to be executed several times per request (for example first for action privileges, later for DLS). Thus,
     * it makes sense to cache and later re-use these.
     */
    private final Map<String, WildcardMatcher> renderedPatternTemplateCache = new HashMap<>();
    private final ImmutableSet<String> mappedRoles;
    private final Supplier<ClusterState> clusterStateSupplier;
    private final IndexResolverReplacer indexResolverReplacer;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    public PrivilegesEvaluationContext(
        User user,
        ImmutableSet<String> mappedRoles,
        String action,
        ActionRequest request,
        Task task,
        Supplier<ClusterState> clusterStateSupplier,
        IndexResolverReplacer indexResolverReplacer,
        IndexNameExpressionResolver indexNameExpressionResolver
    ) {
        this.user = user;
        this.mappedRoles = mappedRoles;
        this.action = action;
        this.request = request;
        this.task = task;
        this.clusterStateSupplier = clusterStateSupplier;
        this.indexResolverReplacer = indexResolverReplacer;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    public User getUser() {
        return user;
    }

    public WildcardMatcher getRenderedMatcher(String template) throws ExpressionEvaluationException {
        WildcardMatcher matcher = this.renderedPatternTemplateCache.get(template);

        if (matcher == null) {
            try {
                matcher = WildcardMatcher.from(UserAttributes.replaceProperties(template, this.user));
            } catch (Exception e) {
                // This especially happens for invalid regular expressions
                throw new ExpressionEvaluationException("Error while evaluating expression in " + template, e);
            }

            this.renderedPatternTemplateCache.put(template, matcher);
        }

        return matcher;
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

    public PrivilegesEvaluationContext mappedRoles(ImmutableSet<String> mappedRoles) {
        if (this.mappedRoles != null && this.mappedRoles.equals(mappedRoles)) {
            return this;
        } else {
            return new PrivilegesEvaluationContext(
                user,
                mappedRoles,
                action,
                request,
                task,
                clusterStateSupplier,
                indexResolverReplacer,
                indexNameExpressionResolver
            );
        }
    }

    public IndexNameExpressionResolver getIndexNameExpressionResolver() {
        return indexNameExpressionResolver;
    }

    public Supplier<ClusterState> getClusterStateSupplier() {
        return clusterStateSupplier;
    }

}
