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
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

public abstract class PrivilegesEvaluationContext {

    private final User user;
    private final String action;
    private final ActionRequest request;
    private IndexResolverReplacer.Resolved resolvedRequest;
    private Map<String, IndexAbstraction> indicesLookup;
    private final Task task;
    private final IndexResolverReplacer indexResolverReplacer;
    private final IndexNameExpressionResolver indexNameExpressionResolver;
    private final Supplier<ClusterState> clusterStateSupplier;

    /**
     * This caches the ready to use WildcardMatcher instances for the current request. Many index patterns have
     * to be executed several times per request (for example first for action privileges, later for DLS). Thus,
     * it makes sense to cache and later re-use these.
     */
    private final Map<String, WildcardMatcher> renderedPatternTemplateCache = new HashMap<>();

    PrivilegesEvaluationContext(
        User user,
        String action,
        ActionRequest request,
        Task task,
        IndexResolverReplacer indexResolverReplacer,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<ClusterState> clusterStateSupplier
    ) {
        this.user = user;
        this.action = action;
        this.request = request;
        this.task = task;
        this.indexResolverReplacer = indexResolverReplacer;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.clusterStateSupplier = clusterStateSupplier;
    }

    public User getUser() {
        return user;
    }

    /**
     * Interpolates any attribute references (like ${user.name}) in the given string and parses the result
     * to a WildcardMatcher. This method catches earlier rendered templates in order to avoid recurring re-rendering
     * of templates during a single privilege evaluation pass.
     *
     * @throws ExpressionEvaluationException if the resulting pattern could not be parsed. This is usually the case
     * if an invalid regex was supplied.
     */
    public WildcardMatcher getRenderedMatcher(String template) throws ExpressionEvaluationException {
        WildcardMatcher matcher = this.renderedPatternTemplateCache.get(template);

        if (matcher == null) {
            try {
                matcher = WildcardMatcher.from(UserAttributes.replaceProperties(template, this));
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

    public Supplier<ClusterState> getClusterStateSupplier() {
        return clusterStateSupplier;
    }

    public Map<String, IndexAbstraction> getIndicesLookup() {
        if (this.indicesLookup == null) {
            this.indicesLookup = clusterStateSupplier.get().metadata().getIndicesLookup();
        }
        return this.indicesLookup;
    }

    public IndexNameExpressionResolver getIndexNameExpressionResolver() {
        return indexNameExpressionResolver;
    }

    public abstract ImmutableSet<String> getMappedRoles();

    abstract void setMappedRoles(ImmutableSet<String> roles);
}
