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
package org.opensearch.security.privileges.actionlevel.nextgen;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.AliasesRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.indices.alias.get.GetAliasesAction;
import org.opensearch.action.admin.indices.alias.get.GetAliasesRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.delete.DeleteAction;
import org.opensearch.action.index.IndexAction;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.update.UpdateAction;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.OptionallyResolvedIndices;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.regex.Regex;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.DocumentAllowList;
import org.opensearch.security.privileges.IndicesRequestModifier;
import org.opensearch.security.privileges.IndicesRequestResolver;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.PrivilegesInterceptor;
import org.opensearch.security.privileges.RoleMapper;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.RuntimeOptimizedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.SubjectBasedActionPrivileges;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SnapshotRestoreHelper;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

public class PrivilegesEvaluator implements org.opensearch.security.privileges.PrivilegesEvaluator {
    private static final Logger log = LogManager.getLogger(PrivilegesEvaluator.class);

    private final Supplier<ClusterState> clusterStateSupplier;
    private final IndexNameExpressionResolver indexNameExpressionResolver;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final PrivilegesInterceptor privilegesInterceptor;
    private final Settings settings;
    private final AtomicReference<RoleBasedActionPrivileges> actionPrivileges = new AtomicReference<>();
    private final ImmutableMap<String, SubjectBasedActionPrivileges> pluginIdToActionPrivileges;
    private final IndicesRequestResolver indicesRequestResolver;
    private final IndicesRequestModifier indicesRequestModifier = new IndicesRequestModifier();
    private final RoleMapper roleMapper;
    private final ThreadPool threadPool;
    private final RuntimeOptimizedActionPrivileges.SpecialIndexProtection specialIndexProtection;
    private final ActionConfiguration actionConfiguration;

    public PrivilegesEvaluator(
        Supplier<ClusterState> clusterStateSupplier,
        RoleMapper roleMapper,
        ThreadPool threadPool,
        ThreadContext threadContext,
        IndexNameExpressionResolver indexNameExpressionResolver,
        AuditLog auditLog,
        Settings settings,
        PrivilegesInterceptor privilegesInterceptor,
        FlattenedActionGroups actionGroups,
        FlattenedActionGroups staticActionGroups,
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
        ConfigV7 generalConfiguration,
        Map<String, RoleV7> pluginIdToRolePrivileges,
        RuntimeOptimizedActionPrivileges.SpecialIndexProtection specialIndexProtection
    ) {
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.auditLog = auditLog;
        this.roleMapper = roleMapper;
        this.threadContext = threadContext;
        this.threadPool = threadPool;
        this.privilegesInterceptor = privilegesInterceptor;
        this.clusterStateSupplier = clusterStateSupplier;
        this.settings = settings;
        this.specialIndexProtection = specialIndexProtection;

        this.actionConfiguration = new ActionConfiguration(settings);
        this.indicesRequestResolver = new IndicesRequestResolver(indexNameExpressionResolver);

        this.pluginIdToActionPrivileges = SubjectBasedActionPrivileges.buildFromMap(
            pluginIdToRolePrivileges,
            staticActionGroups,
            specialIndexProtection
        );
        this.updateConfiguration(actionGroups, rolesConfiguration, generalConfiguration);
    }

    @Override
    public void updateConfiguration(
        FlattenedActionGroups flattenedActionGroups,
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
        ConfigV7 generalConfiguration
    ) {

        try {
            RoleBasedActionPrivileges actionPrivileges = new RoleBasedActionPrivileges(
                rolesConfiguration,
                flattenedActionGroups,
                this.specialIndexProtection,
                this.settings,
                false
            );
            Metadata metadata = clusterStateSupplier.get().metadata();
            actionPrivileges.updateStatefulIndexPrivileges(metadata.getIndicesLookup(), metadata.version());
            RoleBasedActionPrivileges oldInstance = this.actionPrivileges.getAndSet(actionPrivileges);

            if (oldInstance != null) {
                oldInstance.clusterStateMetadataDependentPrivileges().shutdown();
            }
        } catch (Exception e) {
            log.error("Error while updating ActionPrivileges", e);
        }
    }

    @Override
    public PrivilegesEvaluationContext createContext(User user, String action) {
        return createContext(user, action, null, ActionRequestMetadata.empty(), null);
    }

    @Override
    public PrivilegesEvaluationContext createContext(
        User user,
        String action,
        ActionRequest request,
        ActionRequestMetadata<?, ?> actionRequestMetadata,
        Task task
    ) {
        TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        ActionPrivileges actionPrivileges;
        ImmutableSet<String> mappedRoles;

        if (user.isPluginUser()) {
            mappedRoles = ImmutableSet.of();
            actionPrivileges = this.pluginIdToActionPrivileges.get(user.getName());
            if (actionPrivileges == null) {
                actionPrivileges = ActionPrivileges.EMPTY;
            }
        } else {
            mappedRoles = this.roleMapper.map(user, caller);
            actionPrivileges = this.actionPrivileges.get();
        }

        return new PrivilegesEvaluationContext(
            user,
            mappedRoles,
            action,
            request,
            actionRequestMetadata,
            task,
            indexNameExpressionResolver,
            indicesRequestResolver,
            clusterStateSupplier,
            actionPrivileges
        );
    }

    @Override
    public PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context) {
        String action = this.actionConfiguration.normalize(context.getAction());
        if (this.actionConfiguration.isUniversallyDenied(action)) {
            return PrivilegesEvaluatorResponse.insufficient(action).reason("The action is universally denied");
        }

        User user = context.getUser();
        ActionRequest request = context.getRequest();

        ActionPrivileges actionPrivileges = context.getActionPrivileges();
        if (actionPrivileges == null) {
            throw new OpenSearchSecurityException("OpenSearch Security is not initialized: roles configuration is missing");
        }

        if (request instanceof BulkRequest && (Strings.isNullOrEmpty(user.getRequestedTenant()))) {
            // Shortcut for bulk actions. The details are checked on the lower level of the BulkShardRequests (Action
            // indices:data/write/bulk[s]).
            // This shortcut is only possible if the default tenant is selected, as we might need to rewrite the request for non-default
            // tenants.
            // No further access check for the default tenant is necessary, as access will be also checked on the TransportShardBulkAction
            // level.

            PrivilegesEvaluatorResponse result = actionPrivileges.hasClusterPrivilege(context, action);
            logPrivilegeEvaluationResult(context, result, "cluster");
            return result;
        }

        OptionallyResolvedIndices optionallyResolvedIndices = context.getResolvedRequest();
        if (log.isTraceEnabled()) {
            if (request instanceof IndicesRequest indicesRequest) {
                log.trace("IndicesRequest: {} {}", indicesRequest.indices(), indicesRequest.indicesOptions());
            }
            log.trace("ResolvedIndices: {}", optionallyResolvedIndices);
        }

        if (isClusterPermission(action)) {
            PrivilegesEvaluatorResponse result = checkClusterPermission(context, action, request);
            logPrivilegeEvaluationResult(context, result, "cluster");
            return result;
        } else {
            PrivilegesEvaluatorResponse result = checkIndexPermission(context, action, request);
            logPrivilegeEvaluationResult(context, result, "index");
            return result;
        }
    }

    PrivilegesEvaluatorResponse checkClusterPermission(PrivilegesEvaluationContext context, String action, ActionRequest request) {
        if (context.getUser().isServiceAccount()) {
            return PrivilegesEvaluatorResponse.insufficient(action)
                .reason("User is a service account which does not have access to any cluster action");
        }

        PrivilegesEvaluatorResponse presponse = context.getActionPrivileges().hasClusterPrivilege(context, action);
        if (!presponse.isAllowed()) {
            return presponse;
        }

        PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
            request,
            action,
            context.getUser(),
            context.getResolvedRequest(),
            context
        );

        log.trace("Result from privileges interceptor for cluster perm: {}", replaceResult);

        if (!replaceResult.continueEvaluation) {
            if (replaceResult.accessDenied) {
                auditLog.logMissingPrivileges(action, request, context.getTask());
                return PrivilegesEvaluatorResponse.insufficient(action).reason("Insufficient tenant privileges");
            } else {
                return PrivilegesEvaluatorResponse.ok(replaceResult.createIndexRequestBuilder);
            }
        }

        if (request instanceof RestoreSnapshotRequest restoreSnapshotRequest) {
            return handleRestoreSnapshot(context, restoreSnapshotRequest);
        }

        return presponse;
    }

    PrivilegesEvaluatorResponse checkIndexPermission(PrivilegesEvaluationContext context, String action, ActionRequest request) {
        if (DocumentAllowList.isAllowed(request, threadContext)) {
            return PrivilegesEvaluatorResponse.ok();
        }

        OptionallyResolvedIndices optionallyResolvedIndices = context.getResolvedRequest();

        PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
            request,
            action,
            context.getUser(),
            optionallyResolvedIndices,
            context
        );

        log.trace("Result from privileges interceptor: {}", replaceResult);

        if (!replaceResult.continueEvaluation) {
            if (replaceResult.accessDenied) {
                auditLog.logMissingPrivileges(action, request, context.getTask());
                return PrivilegesEvaluatorResponse.insufficient(action).reason("Insufficient tenant privileges");
            } else {
                return PrivilegesEvaluatorResponse.ok(replaceResult.createIndexRequestBuilder);
            }
        }

        if (request instanceof GetAliasesRequest getAliasesRequest
            && optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
            // The GetAliasesAction is such a special thing that we need a special case for it
            return handleGetAliases(context, getAliasesRequest, resolvedIndices);
        }

        return checkIndexPermissionBasic(context, requiredIndexPermissions(request, action), optionallyResolvedIndices, request);
    }

    /**
     * Checks whether the user has the necessary privileges for the given requiredIndexPermissions set and the given
     * resolvedIndices. Reduces the requested indices to authorized indices if possible. This method contains the
     * generic part of the privilege evaluation check; all special cases like Dashboards index handing and similar are
     * in the checkIndexPermission() method.
     */
    PrivilegesEvaluatorResponse checkIndexPermissionBasic(
        PrivilegesEvaluationContext context,
        Set<String> requiredIndexPermissions,
        OptionallyResolvedIndices optionallyResolvedIndices,
        ActionRequest request
    ) {

        ActionPrivileges actionPrivileges = context.getActionPrivileges();

        if (optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices && resolvedIndices.isEmpty()) {
            // If the request is empty, the normal privilege checks would just pass because technically the question
            // "are all indices authorized" is true if the set of indices is empty. This means that certain operations
            // would be available to any users regardless of their privileges. Thus, we check first whether the user
            // has *any* privilege for the given action.
            // The main example for such actions is the _analyze action which can operate on indices, but also can
            // operate on an empty set of indices. Without this check, it would be always allowed.
            PrivilegesEvaluatorResponse anyPrivilegesResult = actionPrivileges.hasIndexPrivilegeForAnyIndex(
                context,
                requiredIndexPermissions
            );
            if (!anyPrivilegesResult.isAllowed()) {
                return anyPrivilegesResult;
            }
        }

        PrivilegesEvaluatorResponse presponse = actionPrivileges.hasIndexPrivilege(
            context,
            requiredIndexPermissions,
            optionallyResolvedIndices
        );

        if (optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices && !resolvedIndices.local().subActions().isEmpty()) {
            // Sub-actions represent situations like a CreateIndexRequest which is configured to add the index also to an alias
            // In these cases, we check also privileges for sub-actions. Sub-actions are not eligible for index reduction,
            // i.e., they can be only successful or fail.
            presponse = checkSubActionPermissions(context, resolvedIndices, presponse);
        }

        if (presponse.isPartiallyOk()) {
            // If the user has privileges only for a sub-set of indices, we try to scope the request only to these indices if the conditions
            // allow.
            // These are:
            // - The action supports it
            // - The index expression contains a pattern expression or ignore_unavailable is true

            if (isIndexReductionForIncompletePrivilegesPossible(request)
                && optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
                if (this.indicesRequestModifier.setLocalIndices(request, resolvedIndices, presponse.getAvailableIndices())) {
                    return PrivilegesEvaluatorResponse.ok().reason("Only allowed for a sub-set of indices").originalResult(presponse);
                }
            }
        } else if (!presponse.isAllowed()) {
            // If the user has no privileges, there are certain conditions where we return an empty result instead of a 403 error
            // These are:
            // - The action supports it
            // - The index expression contains a pattern expression or ignore_unavailable is true
            // - The user has privileges for the given actions on some indices

            if (isIndexReductionForNoPrivilegesPossible(request) && optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
                // We only allow returning empty results if the current user has at least the necessary privileges for any index
                PrivilegesEvaluatorResponse allowedForAnyIndex = actionPrivileges.hasIndexPrivilegeForAnyIndex(
                    context,
                    requiredIndexPermissions
                );

                if (allowedForAnyIndex.isAllowed() && this.indicesRequestModifier.setLocalIndicesToEmpty(request, resolvedIndices)) {
                    return PrivilegesEvaluatorResponse.ok()
                        .reason("Not allowed for any indices; returning empty result")
                        .originalResult(presponse);
                }
            }
        }

        return presponse;
    }

    @Override
    public boolean isClusterPermission(String action) {
        return this.actionConfiguration.isClusterPermission(action);
    }

    @Override
    public void updateClusterStateMetadata(ClusterService clusterService) {
        RoleBasedActionPrivileges actionPrivileges = this.actionPrivileges.get();
        if (actionPrivileges != null) {
            actionPrivileges.clusterStateMetadataDependentPrivileges().updateClusterStateMetadataAsync(clusterService, threadPool);
        }
    }

    @Override
    public void shutdown() {
        RoleBasedActionPrivileges roleBasedActionPrivileges = this.actionPrivileges.get();
        if (roleBasedActionPrivileges != null) {
            roleBasedActionPrivileges.clusterStateMetadataDependentPrivileges().shutdown();
        }
    }

    @Override
    public boolean notFailOnForbiddenEnabled() {
        return true;
    }

    void logPrivilegeEvaluationResult(PrivilegesEvaluationContext context, PrivilegesEvaluatorResponse result, String privilegeType) {
        if (result.isAllowed()) {
            if (log.isDebugEnabled()) {
                String reason = result.getReason();
                if (result.hasEvaluationExceptions()) {
                    reason = "There were errors during privilege evaluation";
                }
                String requestInfo = getRequestInfo(context.getRequest());

                if (reason == null) {
                    log.debug("""
                        Allowing {} action because all privileges are present.
                          Action: {}
                          Request: {}
                          Resolved indices: {}
                          User: {}
                        """, privilegeType, context.getAction(), requestInfo, context.getResolvedRequest(), context.getUser());
                } else if (result.privilegesAreComplete()) {
                    log.debug(
                        """
                            Allowing {} action, but: {}
                              Action: {}
                              Request: {}
                              Resolved indices: {}
                              User: {}
                              Roles: {}
                              Errors: {}
                            """,
                        privilegeType,
                        reason,
                        context.getAction(),
                        requestInfo,
                        context.getResolvedRequest(),
                        context.getUser(),
                        context.getMappedRoles(),
                        result.getEvaluationExceptionInfo()
                    );
                } else {
                    log.debug(
                        """
                            Allowing {} action, but: {}
                              Action: {}
                              Request: {}
                              Resolved indices: {}
                              User: {}
                              Roles: {}
                              Available privileges:
                            {}
                              Errors: {}
                            """,
                        privilegeType,
                        reason,
                        context.getAction(),
                        requestInfo,
                        context.getResolvedRequest(),
                        context.getUser(),
                        context.getMappedRoles(),
                        result.originalResult() != null ? result.originalResult().getPrivilegeMatrix() : result.getPrivilegeMatrix(),
                        result.getEvaluationExceptionInfo()
                    );
                }
            }
        } else {
            log.info(
                """
                    Not allowing {} action: {}
                      Action: {}
                      Request: {}
                      Resolved indices: {}
                      User: {}
                      Roles: {}
                      Available privileges:
                    {}
                      Errors: {}
                    """,
                privilegeType,
                result.getReason(),
                context.getAction(),
                getRequestInfo(context.getRequest()),
                context.getResolvedRequest(),
                context.getUser(),
                context.getMappedRoles(),
                result.originalResult() != null ? result.originalResult().getPrivilegeMatrix() : result.getPrivilegeMatrix(),
                result.getEvaluationExceptionInfo()
            );
        }
    }

    String getRequestInfo(ActionRequest request) {
        StringBuilder result = new StringBuilder(request.getClass().getSimpleName());
        if (request instanceof IndicesRequest indicesRequest) {
            String[] indices = indicesRequest.indices();
            result.append("; indices: ").append(indices != null ? Arrays.asList(indices) : "null");
            result.append("; indicesOptions: ").append(indicesRequest.indicesOptions());
        }
        if (request instanceof AliasesRequest aliasesRequest) {
            String[] aliases = aliasesRequest.aliases();
            result.append("; aliases: ").append(aliases != null ? Arrays.asList(aliases) : "null");
        }
        return result.toString();
    }

    /**
     * The GetAliasesRequest has such a complicated logic that we need to handle it with a special case. It has two dimensions:
     * indices and aliases which can be independently specified; indices can be reduced, but reducing aliases is not really
     * possible due to a special logic which exists in the RestGetAliasesAction (an unusual location for such logic):
     * https://github.com/opensearch-project/OpenSearch/blob/1df543e04d7605b7ee37587ff5c635609ebdafbd/server/src/main/java/org/opensearch/rest/action/admin/indices/RestGetAliasesAction.java#L94
     * Another effect of this logic is that if there are explicitly specified aliases in the request which are not matched
     * by any indices, the action fails with a 404 error.
     * In order to avoid these 404 errors, we fail with an "insufficient" error whenever there are explicit aliases
     * and there are no sufficient privileges for these aliases.
     * If there are no explicit aliases, we can do index reduction, though.
     */
    PrivilegesEvaluatorResponse handleGetAliases(
        PrivilegesEvaluationContext context,
        GetAliasesRequest request,
        ResolvedIndices resolvedIndices
    ) {
        ActionPrivileges actionPrivileges = context.getActionPrivileges();
        String aliasesSubActionKey = GetAliasesAction.NAME + "[aliases]";
        Set<String> indices = resolvedIndices.local().names();
        Set<String> aliases = resolvedIndices.local().subActions().containsKey(aliasesSubActionKey)
            ? resolvedIndices.local().subActions().get(aliasesSubActionKey).names()
            : Collections.emptySet();

        PrivilegesEvaluatorResponse indicesResult = actionPrivileges.hasIndexPrivilege(
            context,
            Set.of(context.getAction()),
            ResolvedIndices.of(indices)
        );
        PrivilegesEvaluatorResponse aliasesResult = actionPrivileges.hasIndexPrivilege(
            context,
            Set.of(context.getAction()),
            ResolvedIndices.of(aliases)
        );

        if (!aliasesResult.isAllowed() && request.aliases().length != 0) {
            // The RestGetAliasesAction does not allow reducing aliases (Even though the GetAliasesRequest has a method for
            // setting aliases retroactively). Thus, if explicit aliases were specified, we will always fail with an
            // "insufficient" error.
            return indicesResult.insufficient(List.of(aliasesResult))
                .reason("No privileges for aliases while explicit aliases were specified in the request");
        }

        if (!indicesResult.isAllowed() && indicesResult.getAvailableIndices().isEmpty()) {
            // If the user does not have privileges for any index, we deny the request here completely
            PrivilegesEvaluatorResponse anyPrivilegesResult = actionPrivileges.hasIndexPrivilegeForAnyIndex(
                context,
                Set.of(context.getAction())
            );
            if (anyPrivilegesResult != null && !anyPrivilegesResult.isAllowed()) {
                return indicesResult;
            }
        }

        if (!indicesResult.isAllowed()) {
            // If we reached this block, the user has privileges for a sub-set of indices or at least for other indices.
            // Then, we will return either a reduced or empty result
            if (this.indicesRequestModifier.setLocalIndices(request, resolvedIndices, indicesResult.getAvailableIndices())) {
                return PrivilegesEvaluatorResponse.ok()
                    .originalResult(indicesResult)
                    .reason(
                        indicesResult.isPartiallyOk()
                            ? "Only allowed for a subset of indices"
                            : "Not allowed for any indices; returning empty result"
                    );
            }
        }

        return indicesResult;
    }

    /**
     * Special handling for RestoreSnapshotRequests. This includes especially the check of the privileges for the restored
     * indices. The check will be performed using the standard checkIndexPermission() method; thus, the standard restrictions
     * on the security index and system indices apply (incl. system index permission handling).
     */
    PrivilegesEvaluatorResponse handleRestoreSnapshot(PrivilegesEvaluationContext context, RestoreSnapshotRequest request) {
        if (request.includeGlobalState()) {
            return PrivilegesEvaluatorResponse.insufficient(context.getAction())
                .reason("Restoring snapshot with 'include_global_state' enabled is not allowed");
        }

        if (!clusterStateSupplier.get().nodes().isLocalNodeElectedClusterManager()) {
            // We need to return ok here, because we can only retrieve the snapshot info on a cluster manager node.
            // This is fine, as the next thing the TransportAction implementation will do, is forwarding the request to a
            // cluster manager node.
            return PrivilegesEvaluatorResponse.ok();
        }

        OptionallyResolvedIndices optionallyResolvedIndices = SnapshotRestoreHelper.resolveTargetIndices(request);
        if (!(optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices)) {
            return PrivilegesEvaluatorResponse.insufficient(context.getAction())
                .reason("Could not retrieve information for snapshot " + request.repository() + "/" + request.snapshot());
        }

        return checkIndexPermissionBasic(
            context,
            ConfigConstants.SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES,
            resolvedIndices,
            request
        );
    }

    PrivilegesEvaluatorResponse checkSubActionPermissions(
        PrivilegesEvaluationContext context,
        ResolvedIndices resolvedIndices,
        PrivilegesEvaluatorResponse originalResult
    ) {
        ActionPrivileges actionPrivileges = context.getActionPrivileges();
        List<PrivilegesEvaluatorResponse> subActionResults = new ArrayList<>(resolvedIndices.local().subActions().size());
        boolean allowed = true;

        for (Map.Entry<String, ResolvedIndices.Local> subAction : resolvedIndices.local().subActions().entrySet()) {
            PrivilegesEvaluatorResponse subResponse = actionPrivileges.hasIndexPrivilege(
                context,
                Set.of(subAction.getKey()),
                ResolvedIndices.of(subAction.getValue())
            );
            subActionResults.add(subResponse);
            if (!subResponse.isAllowed()) {
                allowed = false;
            }
        }
        if (allowed) {
            return originalResult;
        } else {
            return originalResult.insufficient(subActionResults);
        }
    }

    Set<String> requiredIndexPermissions(ActionRequest request, String originalAction) {
        if (request instanceof ClusterSearchShardsRequest) {
            return Set.of(originalAction, SearchAction.NAME);
        } else if (request instanceof BulkShardRequest bulkShardRequest) {
            ImmutableSet.Builder<String> allRequiredPermissions = ImmutableSet.builderWithExpectedSize(2);
            allRequiredPermissions.add(originalAction);
            for (BulkItemRequest item : bulkShardRequest.items()) {
                switch (item.request().opType()) {
                    case CREATE:
                    case INDEX:
                        allRequiredPermissions.add(IndexAction.NAME);
                        break;
                    case DELETE:
                        allRequiredPermissions.add(DeleteAction.NAME);
                        break;
                    case UPDATE:
                        allRequiredPermissions.add(UpdateAction.NAME);
                        break;
                }
            }
            return allRequiredPermissions.build();
        } else {
            return Set.of(originalAction);
        }
    }

    boolean isIndexReductionForIncompletePrivilegesPossible(ActionRequest request) {
        if (!(request instanceof IndicesRequest.Replaceable indicesRequest)) {
            return false;
        }

        if (indicesRequest.indicesOptions().ignoreUnavailable()) {
            return true;
        }

        return indicesRequest.indicesOptions().expandWildcardsOpen() && containsPattern(indicesRequest);
    }

    boolean isIndexReductionForNoPrivilegesPossible(ActionRequest request) {
        if (!isIndexReductionForIncompletePrivilegesPossible(request)) {
            return false;
        }

        if (request instanceof CreatePitRequest) {
            // The creation of PIT search contexts is not possible for no indices
            return false;
        }

        return ((IndicesRequest) request).indicesOptions().allowNoIndices();
    }

    boolean containsPattern(IndicesRequest indicesRequest) {
        String[] indices = indicesRequest.indices();

        if (indices == null
            || indices.length == 0
            || (indices.length == 1 && (Metadata.ALL.equals(indices[0]) || Regex.isMatchAllPattern(indices[0])))) {
            return true;
        }

        for (String index : indices) {
            if (Regex.isSimpleMatchPattern(index)) {
                return true;
            }
        }

        return false;
    }
}
