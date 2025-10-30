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
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.security.support.WildcardMatcher;
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
public class PrivilegesEvaluationContext {
    private final User user;
    private final String action;
    private final ActionRequest request;
    private OptionallyResolvedIndices resolvedIndices;
    private Map<String, IndexAbstraction> indicesLookup;
    private final Task task;
    private ImmutableSet<String> mappedRoles;
    private final IndexNameExpressionResolver indexNameExpressionResolver;
    private final IndicesRequestResolver indicesRequestResolver;
    private final Supplier<ClusterState> clusterStateSupplier;
    private final ActionRequestMetadata<?, ?> actionRequestMetadata;

    /**
     * Stores the ActionPrivileges instance to be used for this request. Plugin system users or users created from
     * API tokens might use ActionPrivileges instances which do not correspond to the normal role configuration.
     */
    private final ActionPrivileges actionPrivileges;

    /**
     * This caches the ready to use WildcardMatcher instances for the current request. Many index patterns have
     * to be executed several times per request (for example first for action privileges, later for DLS). Thus,
     * it makes sense to cache and later re-use these.
     */
    private final Map<String, WildcardMatcher> renderedPatternTemplateCache = new HashMap<>();

    public PrivilegesEvaluationContext(
        User user,
        ImmutableSet<String> mappedRoles,
        String action,
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        Task task,
        IndexNameExpressionResolver indexNameExpressionResolver,
        IndicesRequestResolver indicesRequestResolver,
        Supplier<ClusterState> clusterStateSupplier,
        ActionPrivileges actionPrivileges
    ) {
        this.user = user;
        this.mappedRoles = mappedRoles;
        this.action = action;
        this.request = request;
        this.clusterStateSupplier = clusterStateSupplier;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.indicesRequestResolver = indicesRequestResolver;
        this.task = task;
        this.actionRequestMetadata = actionRequestMetadata;
        this.actionPrivileges = actionPrivileges;
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

    public OptionallyResolvedIndices getResolvedRequest() {
        OptionallyResolvedIndices result = this.resolvedIndices;
        if (result == null) {
            this.resolvedIndices = result = this.indicesRequestResolver.resolve(
                this.request,
                this.actionRequestMetadata,
                this.clusterStateSupplier
            );
        }

        return result;
    }

    public Task getTask() {
        return task;
    }

    public ImmutableSet<String> getMappedRoles() {
        return mappedRoles;
    }

    public ClusterState clusterState() {
        return clusterStateSupplier.get();
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

    /**
     * Returns the ActionPrivileges instance to be used for this request. Plugin system users or users created from
     * API tokens might use ActionPrivileges instances which do not correspond to the normal role configuration.
     */
    public ActionPrivileges getActionPrivileges() {
        return actionPrivileges;
    }

    @Override
    public String toString() {
        return "PrivilegesEvaluationContext{"
            + "user="
            + user
            + ", action='"
            + action
            + '\''
            + ", request="
            + request
            + ", resolvedIndices="
            + resolvedIndices
            + ", mappedRoles="
            + mappedRoles
            + '}';
    }
}
