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
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;

import org.opensearch.action.ActionRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.security.action.apitokens.ApiTokenRepository;
import org.opensearch.security.action.apitokens.Permissions;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;

import static org.opensearch.security.http.ApiTokenAuthenticator.API_TOKEN_USER_PREFIX;

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
    private IndexResolverReplacer.Resolved resolvedRequest;
    private Map<String, IndexAbstraction> indicesLookup;
    private final Task task;
    private ImmutableSet<String> mappedRoles;
    private final IndexResolverReplacer indexResolverReplacer;
    private final IndexNameExpressionResolver indexNameExpressionResolver;
    private final Supplier<ClusterState> clusterStateSupplier;
    private final Permissions permissionsForApiToken;
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
        Task task,
        IndexResolverReplacer indexResolverReplacer,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<ClusterState> clusterStateSupplier,
        ApiTokenRepository apiTokenRepository
    ) {
        this.user = user;
        this.mappedRoles = mappedRoles;
        this.action = action;
        this.request = request;
        this.clusterStateSupplier = clusterStateSupplier;
        this.indexResolverReplacer = indexResolverReplacer;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.task = task;
        this.permissionsForApiToken = extractApiTokenPermissionsForUser(apiTokenRepository);
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
            + ", resolvedRequest="
            + resolvedRequest
            + ", mappedRoles="
            + mappedRoles
            + '}';
    }

    public Permissions getPermissionsForApiToken() {
        return permissionsForApiToken;
    }

    @VisibleForTesting
    PrivilegesEvaluationContext(
        User user,
        ImmutableSet<String> mappedRoles,
        String action,
        ActionRequest request,
        Task task,
        IndexResolverReplacer indexResolverReplacer,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<ClusterState> clusterStateSupplier,
        Permissions permissions
    ) {
        this.user = user;
        this.mappedRoles = mappedRoles;
        this.action = action;
        this.request = request;
        this.clusterStateSupplier = clusterStateSupplier;
        this.indexResolverReplacer = indexResolverReplacer;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.task = task;
        this.permissionsForApiToken = permissions;
    }

    private Permissions extractApiTokenPermissionsForUser(ApiTokenRepository apiTokenRepository) {
        if (user.getName().startsWith(API_TOKEN_USER_PREFIX)) {
            String jti = user.getName().split(API_TOKEN_USER_PREFIX)[1];
            if (apiTokenRepository.isValidToken(jti)) {
                return apiTokenRepository.getPermissionsForJti(jti);
            }
        }
        return new Permissions(List.of(), List.of());
    }
}
