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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

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
import org.opensearch.action.admin.indices.template.delete.DeleteComposableIndexTemplateAction;
import org.opensearch.action.admin.indices.template.delete.DeleteIndexTemplateAction;
import org.opensearch.action.admin.indices.template.get.GetComposableIndexTemplateAction;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesAction;
import org.opensearch.action.admin.indices.template.post.SimulateIndexTemplateAction;
import org.opensearch.action.admin.indices.template.post.SimulateTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateAction;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.delete.DeleteAction;
import org.opensearch.action.get.GetRequest;
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
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.MultiSearchTemplateAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;
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
import org.opensearch.security.privileges.actionlevel.WellKnownActions;
import org.opensearch.security.privileges.actionlevel.legacy.SnapshotRestoreEvaluator;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

public class PrivilegesEvaluator implements org.opensearch.security.privileges.PrivilegesEvaluator {
    private static final Logger log = LogManager.getLogger(PrivilegesEvaluator.class);

    private final Supplier<ClusterState> clusterStateSupplier;
    private final IndexNameExpressionResolver resolver;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final PrivilegesInterceptor privilegesInterceptor;
    private final boolean checkSnapshotRestoreWritePrivileges;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final Settings settings;
    private final AtomicReference<RoleBasedActionPrivileges> actionPrivileges = new AtomicReference<>();
    private final Map<String, SubjectBasedActionPrivileges> pluginIdToActionPrivileges = new HashMap<>();
    private final IndicesRequestResolver indicesRequestResolver;
    private final IndicesRequestModifier indicesRequestModifier = new IndicesRequestModifier();
    private final RoleMapper roleMapper;
    private final ThreadPool threadPool;
    private final RuntimeOptimizedActionPrivileges.SpecialIndexProtection specialIndexProtection;
    private final ImmutableSet<String> explicitIndexActions;
    private final ImmutableSet<String> clusterActions;
    private final ActionNameMapping actionNameMapping;

    public PrivilegesEvaluator(
        ClusterService clusterService,
        Supplier<ClusterState> clusterStateSupplier,
        RoleMapper roleMapper,
        ThreadPool threadPool,
        ThreadContext threadContext,
        IndexNameExpressionResolver resolver,
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

        super();
        this.resolver = resolver;
        this.auditLog = auditLog;
        this.roleMapper = roleMapper;

        this.threadContext = threadContext;
        this.threadPool = threadPool;
        this.privilegesInterceptor = privilegesInterceptor;
        this.clusterStateSupplier = clusterStateSupplier;
        this.settings = settings;
        this.specialIndexProtection = specialIndexProtection;
        this.explicitIndexActions = createExplicitIndexActionSet(settings);
        this.clusterActions = createClusterActionSet(settings);
        this.actionNameMapping = new ActionNameMapping(settings);

        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(
            ConfigConstants.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
            ConfigConstants.SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES
        );

        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(
            settings,
            auditLog,
            clusterService != null ? () -> clusterService.state().nodes().isLocalNodeElectedClusterManager() : () -> false
        );

        this.indicesRequestResolver = new IndicesRequestResolver(resolver);

        this.pluginIdToActionPrivileges.putAll(
            createActionPrivileges(pluginIdToRolePrivileges, staticActionGroups, specialIndexProtection)
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
        String action0,
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
            action0,
            request,
            actionRequestMetadata,
            task,
            resolver,
            indicesRequestResolver,
            clusterStateSupplier,
            actionPrivileges
        );
    }

    @Override
    public PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context) {
        String action = this.actionNameMapping.normalize(context.getAction());
        User user = context.getUser();
        ActionRequest request = context.getRequest();
        Task task = context.getTask();

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
        } else if (request instanceof RestoreSnapshotRequest) {
            PrivilegesEvaluatorResponse result = snapshotRestoreEvaluator.evaluate(request, task, action);
            if (result != null) {
                logPrivilegeEvaluationResult(context, result, "cluster");
                return result;
            }
        }

        OptionallyResolvedIndices optionallyResolvedIndices = context.getResolvedRequest();
        if (log.isTraceEnabled()) {
            if (request instanceof IndicesRequest indicesRequest) {
                log.trace("IndicesRequest: {} {}", indicesRequest.indices(), indicesRequest.indicesOptions());
            }
            log.trace("ResolvedIndices: {}", optionallyResolvedIndices);
        }

        if (isClusterPermission(action)) {
            PrivilegesEvaluatorResponse result = checkClusterPermission(context, action, request, user);
            logPrivilegeEvaluationResult(context, result, "cluster");
            return result;
        } else {
            PrivilegesEvaluatorResponse result = checkIndexPermission(context, action, request, user);
            logPrivilegeEvaluationResult(context, result, "index");
            return result;
        }
    }

    PrivilegesEvaluatorResponse checkClusterPermission(
        PrivilegesEvaluationContext context,
        String action,
        ActionRequest request,
        User user
    ) {
        if (user.isServiceAccount()) {
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
            user,
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

        if (request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
            // TODO
        }

        return presponse;
    }

    PrivilegesEvaluatorResponse checkIndexPermission(PrivilegesEvaluationContext context, String action, ActionRequest request, User user) {
        if (checkDocAllowListHeader(user, action, request)) {
            return PrivilegesEvaluatorResponse.ok();
        }

        OptionallyResolvedIndices optionallyResolvedIndices = context.getResolvedRequest();
        ActionPrivileges actionPrivileges = context.getActionPrivileges();

        PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
            request,
            action,
            user,
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

        ImmutableSet<String> requiredIndexPermissions = requiredIndexPermissions(request, action);

        PrivilegesEvaluatorResponse presponse = actionPrivileges.hasIndexPrivilege(
            context,
            requiredIndexPermissions,
            optionallyResolvedIndices
        );

        if (optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices && !resolvedIndices.local().subActions().isEmpty()) {
            presponse = checkSubActionPermissions(context, resolvedIndices, presponse);
        }

        if (presponse.isPartiallyOk()) {
            if (isIndexReductionForIncompletePrivilegesPossible(request)
                && optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
                if (this.indicesRequestModifier.setLocalIndices(request, resolvedIndices, presponse.getAvailableIndices())) {
                    return PrivilegesEvaluatorResponse.ok().reason("Only allowed for a sub-set of indices").originalResult(presponse);
                }
            }
        } else if (!presponse.isAllowed()) {
            if (isIndexReductionForNoPrivilegesPossible(request) && optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
                if (this.indicesRequestModifier.setLocalIndicesToEmpty(request, resolvedIndices)) {
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
        if (this.explicitIndexActions.contains(action)) {
            return false;
        } else if (this.clusterActions.contains(action)) {
            return true;
        } else {
            return action.startsWith("cluster:")
                || action.startsWith("indices:admin/template/")
                || action.startsWith("indices:admin/index_template/");
        }
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

        if (!indicesResult.isAllowed()) {
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

    private boolean checkDocAllowListHeader(User user, String action, ActionRequest request) {
        String docAllowListHeader = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER);

        if (docAllowListHeader == null) {
            return false;
        }

        if (!(request instanceof GetRequest getRequest)) {
            return false;
        }

        try {
            DocumentAllowList documentAllowList = DocumentAllowList.parse(docAllowListHeader);

            if (documentAllowList.isAllowed(getRequest.index(), getRequest.id())) {
                if (log.isDebugEnabled()) {
                    log.debug("Request " + request + " is allowed by " + documentAllowList);
                }

                return true;
            } else {
                return false;
            }

        } catch (Exception e) {
            log.error("Error while handling document allow list: " + docAllowListHeader, e);
            return false;
        }
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

    boolean sameIndicesAcrossAllActions(OptionallyResolvedIndices optionallyResolvedIndices) {
        if (!(optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices)) {
            return true;
        }
        if (resolvedIndices.local().subActions().isEmpty()) {
            return true;
        }
        for (ResolvedIndices.Local subActionIndices : resolvedIndices.local().subActions().values()) {
            if (!subActionIndices.names().equals(resolvedIndices.local().names())) {
                return false;
            }
        }
        return true;
    }

    Set<String> namesOfSubActions(OptionallyResolvedIndices optionallyResolvedIndices) {
        if (!(optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices)) {
            return Collections.emptySet();
        }
        return resolvedIndices.local().subActions().keySet();
    }

    private static Map<String, SubjectBasedActionPrivileges> createActionPrivileges(
        Map<String, RoleV7> pluginIdToRolePrivileges,
        FlattenedActionGroups staticActionGroups,
        RuntimeOptimizedActionPrivileges.SpecialIndexProtection specialIndexProtection
    ) {
        Map<String, SubjectBasedActionPrivileges> result = new HashMap<>(pluginIdToRolePrivileges.size());

        for (Map.Entry<String, RoleV7> entry : pluginIdToRolePrivileges.entrySet()) {
            result.put(
                entry.getKey(),
                new SubjectBasedActionPrivileges(entry.getValue(), staticActionGroups, specialIndexProtection, false)
            );
        }

        return result;
    }

    private ImmutableSet<String> requiredIndexPermissions(final ActionRequest request, final String originalAction) {
        ImmutableSet.Builder<String> allRequiredPermissions = ImmutableSet.builderWithExpectedSize(2);

        if (!isClusterPermission(originalAction)) {
            allRequiredPermissions.add(originalAction);
        }

        if (request instanceof ClusterSearchShardsRequest) {
            allRequiredPermissions.add(SearchAction.NAME);
        }

        if (request instanceof BulkShardRequest) {
            BulkShardRequest bsr = (BulkShardRequest) request;
            for (BulkItemRequest bir : bsr.items()) {
                switch (bir.request().opType()) {
                    case CREATE:
                        allRequiredPermissions.add(IndexAction.NAME);
                        break;
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
        }

        if (request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
            allRequiredPermissions.addAll(ConfigConstants.SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES);
        }

        return allRequiredPermissions.build();
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

    ImmutableSet<String> createClusterActionSet(Settings settings) {
        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        builder.addAll(WellKnownActions.CLUSTER_ACTIONS);
        builder.add(MultiSearchTemplateAction.NAME);
        builder.add(ReindexAction.NAME);
        builder.add(RenderSearchTemplateAction.NAME);
        builder.add(PutIndexTemplateAction.NAME);
        builder.add(DeleteIndexTemplateAction.NAME);
        builder.add(GetIndexTemplatesAction.NAME);
        builder.add(PutComposableIndexTemplateAction.NAME);
        builder.add(DeleteComposableIndexTemplateAction.NAME);
        builder.add(GetComposableIndexTemplateAction.NAME);
        builder.add(SimulateIndexTemplateAction.NAME);
        builder.add(SimulateTemplateAction.NAME);
        return builder.build();
    }

    ImmutableSet<String> createExplicitIndexActionSet(Settings settings) {
        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        builder.addAll(WellKnownActions.INDEX_ACTIONS);
        return builder.build();
    }
}
