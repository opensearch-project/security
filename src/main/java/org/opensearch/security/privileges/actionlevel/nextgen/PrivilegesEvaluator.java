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

import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesAction;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.AutoCreateAction;
import org.opensearch.action.admin.indices.create.CreateIndexAction;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.delete.DeleteIndexAction;
import org.opensearch.action.admin.indices.mapping.get.GetFieldMappingsRequest;
import org.opensearch.action.admin.indices.mapping.put.AutoPutMappingAction;
import org.opensearch.action.admin.indices.mapping.put.PutMappingAction;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.delete.DeleteAction;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.MultiGetAction;
import org.opensearch.action.index.IndexAction;
import org.opensearch.action.search.MultiSearchAction;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchScrollAction;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.termvectors.MultiTermVectorsAction;
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
import org.opensearch.security.privileges.actionlevel.legacy.ProtectedIndexAccessEvaluator;
import org.opensearch.security.privileges.actionlevel.legacy.SnapshotRestoreEvaluator;
import org.opensearch.security.privileges.actionlevel.legacy.SystemIndexAccessEvaluator;
import org.opensearch.security.privileges.actionlevel.legacy.TermsAggregationEvaluator;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.opensearch.security.OpenSearchSecurityPlugin.traceAction;

public class PrivilegesEvaluator  implements org.opensearch.security.privileges.PrivilegesEvaluator  {
    private static final Logger log = LogManager.getLogger(PrivilegesEvaluator.class);

    private final Supplier<ClusterState> clusterStateSupplier;
    private final IndexNameExpressionResolver resolver;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final PrivilegesInterceptor privilegesInterceptor;
    private final boolean checkSnapshotRestoreWritePrivileges;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;
    private final Settings settings;
    private final AtomicReference<RoleBasedActionPrivileges> actionPrivileges = new AtomicReference<>();
    private final Map<String, SubjectBasedActionPrivileges> pluginIdToActionPrivileges = new HashMap<>();
    private final IndicesRequestResolver indicesRequestResolver;
    private final IndicesRequestModifier indicesRequestModifier = new IndicesRequestModifier();
    private final RoleMapper roleMapper;
    private final ThreadPool threadPool;
    private final RuntimeOptimizedActionPrivileges.SpecialIndexProtection specialIndexProtection;


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

        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(
                ConfigConstants.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES
        );

        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(
                settings,
                auditLog,
                clusterService != null ? () -> clusterService.state().nodes().isLocalNodeElectedClusterManager() : () -> false
        );

        termsAggregationEvaluator = new TermsAggregationEvaluator();
        this.indicesRequestResolver = new IndicesRequestResolver(resolver);

        this.pluginIdToActionPrivileges.putAll(createActionPrivileges(pluginIdToRolePrivileges, staticActionGroups, specialIndexProtection));
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
                    this.settings
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

        String action0 = context.getAction();
        ImmutableSet<String> mappedRoles = context.getMappedRoles();
        User user = context.getUser();
        ActionRequest request = context.getRequest();
        Task task = context.getTask();

        if (action0.startsWith("internal:indices/admin/upgrade")) {
            action0 = "indices:admin/upgrade";
        }

        if (AutoCreateAction.NAME.equals(action0)) {
            action0 = CreateIndexAction.NAME;
        }

        if (AutoPutMappingAction.NAME.equals(action0)) {
            action0 = PutMappingAction.NAME;
        }

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {}", user);
            log.debug("Action: {} ({})", action0, request.getClass().getSimpleName());
            log.debug("Mapped roles: {}", mappedRoles.toString());
        }

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

            PrivilegesEvaluatorResponse presponse = actionPrivileges.hasClusterPrivilege(context, action0);

            if (!presponse.isAllowed()) {
                log.info(
                        "No cluster-level perm match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}",
                        user,
                        action0,
                        mappedRoles,
                        presponse.getMissingPrivileges()
                );
            }
            return presponse;
        }

        {
            PrivilegesEvaluatorResponse         presponse = snapshotRestoreEvaluator.evaluate(request, task, action0);
            if (presponse != null) {
                return presponse;
            }
        }

        OptionallyResolvedIndices optionallyResolvedIndices = context.getResolvedRequest();

        if (isClusterPermission(action0)) {
            if (user.isServiceAccount()) {
                log.info("{} is a service account which doesn't have access to cluster level permission: {}", user, action0);
                return PrivilegesEvaluatorResponse.insufficient(action0);
            }

            PrivilegesEvaluatorResponse presponse = actionPrivileges.hasClusterPrivilege(context, action0);

            if (!presponse.isAllowed()) {
                log.info(
                        "No cluster-level perm match for {} {} [Action [{}]] [RolesChecked {}]. No permissions for {}",
                        user,
                        optionallyResolvedIndices,
                        action0,
                        mappedRoles,
                        presponse.getMissingPrivileges()
                );
                return presponse;
            } else {

                if (request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
                    if (isDebugEnabled) {
                        log.debug("Normally allowed but we need to apply some extra checks for a restore request.");
                    }
                } else {

                    PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
                                request,
                                action0,
                                user,
                                optionallyResolvedIndices,
                                context
                        );

                        if (isDebugEnabled) {
                            log.debug("Result from privileges interceptor for cluster perm: {}", replaceResult);
                        }

                        if (!replaceResult.continueEvaluation) {
                            if (replaceResult.accessDenied) {
                                auditLog.logMissingPrivileges(action0, request, task);
                                return PrivilegesEvaluatorResponse.insufficient(action0);
                            } else {
                                return PrivilegesEvaluatorResponse.ok(replaceResult.createIndexRequestBuilder);
                            }
                        }
                    }

                    if (isDebugEnabled) {
                        log.debug("Allowed because we have cluster permissions for {}", action0);
                    }
                    return presponse;
                }

        }

        if (checkDocAllowListHeader(user, action0, request)) {
            return PrivilegesEvaluatorResponse.ok();
        }

        {
            PrivilegesEvaluatorResponse presponse = termsAggregationEvaluator.evaluate(optionallyResolvedIndices, request, context, actionPrivileges);
            if (presponse != null) {
                return presponse;
            }
        }

        ImmutableSet<String> allIndexPermsRequired = evaluateAdditionalIndexPermissions(request, action0);

            final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
                    request,
                    action0,
                    user,
                    optionallyResolvedIndices,
                    context
            );

            if (isDebugEnabled) {
                log.debug("Result from privileges interceptor: {}", replaceResult);
            }

            if (!replaceResult.continueEvaluation) {
                if (replaceResult.accessDenied) {
                    auditLog.logMissingPrivileges(action0, request, task);
                    return PrivilegesEvaluatorResponse.insufficient(action0);
                } else {
                    return PrivilegesEvaluatorResponse.ok(replaceResult.createIndexRequestBuilder);
                }
            }


        PrivilegesEvaluatorResponse presponse = actionPrivileges.hasIndexPrivilege(context, allIndexPermsRequired, optionallyResolvedIndices);

        if (presponse.isPartiallyOk()) {
            if (isIndexReductionForIncompletePrivilegesPossible(request) && optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
                if (this.indicesRequestModifier.setLocalIndices(request, resolvedIndices, presponse.getAvailableIndices())) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }
        } else if (!presponse.isAllowed()) {
            if (isIndexReductionForNoPrivilegesPossible(request) && optionallyResolvedIndices instanceof ResolvedIndices resolvedIndices) {
                indicesRequestModifier.setLocalIndicesToEmpty(request, resolvedIndices);
                return PrivilegesEvaluatorResponse.ok();
            }
        }

        if (presponse.isAllowed()) {

                log.debug("Allowed because we have all indices permissions for {}", action0);
        } else {
            log.info(
                    "No {}-level perm match for {} {}: {} [Action [{}]] [RolesChecked {}]",
                    "index",
                    user,
                    optionallyResolvedIndices,
                    presponse.getReason(),
                    action0,
                    mappedRoles
            );
            log.info("Index to privilege matrix:\n{}", presponse.getPrivilegeMatrix());
            if (presponse.hasEvaluationExceptions()) {
                log.info("Evaluation errors:\n{}", presponse.getEvaluationExceptionInfo());
            }
        }

        return presponse;
    }

    @Override
    public boolean isClusterPermission(String action) {
        return (action.startsWith("cluster:")
                || action.startsWith("indices:admin/template/")
                || action.startsWith("indices:admin/index_template/")
                || action.startsWith(SearchScrollAction.NAME)
                || (action.equals(BulkAction.NAME))
                || (action.equals(MultiGetAction.NAME))
                || (action.startsWith(MultiSearchAction.NAME))
                || (action.equals(MultiTermVectorsAction.NAME))
                || (action.equals(ReindexAction.NAME))
                || (action.equals(RenderSearchTemplateAction.NAME)));    }

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

    private boolean checkDocAllowListHeader(User user, String action, ActionRequest request) {
        String docAllowListHeader = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER);

        if (docAllowListHeader == null) {
            return false;
        }

        if (!(request instanceof GetRequest)) {
            return false;
        }

        try {
            DocumentAllowList documentAllowList = DocumentAllowList.parse(docAllowListHeader);
            GetRequest getRequest = (GetRequest) request;

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


    private static Map<String, SubjectBasedActionPrivileges> createActionPrivileges(
            Map<String, RoleV7> pluginIdToRolePrivileges,
            FlattenedActionGroups staticActionGroups,
            RuntimeOptimizedActionPrivileges.SpecialIndexProtection specialIndexProtection
    ) {
        Map<String, SubjectBasedActionPrivileges> result = new HashMap<>(pluginIdToRolePrivileges.size());

        for (Map.Entry<String, RoleV7> entry : pluginIdToRolePrivileges.entrySet()) {
            result.put(
                    entry.getKey(),
                    new SubjectBasedActionPrivileges(
                            entry.getValue(),
                            staticActionGroups,
                            specialIndexProtection
                    )
            );
        }

        return result;
    }

    private ImmutableSet<String> evaluateAdditionalIndexPermissions(final ActionRequest request, final String originalAction) {
        ImmutableSet.Builder<String> additionalPermissionsRequired = ImmutableSet.builder();

        if (!isClusterPermission(originalAction)) {
            additionalPermissionsRequired.add(originalAction);
        }

        if (request instanceof ClusterSearchShardsRequest) {
            additionalPermissionsRequired.add(SearchAction.NAME);
        }

        if (request instanceof BulkShardRequest) {
            BulkShardRequest bsr = (BulkShardRequest) request;
            for (BulkItemRequest bir : bsr.items()) {
                switch (bir.request().opType()) {
                    case CREATE:
                        additionalPermissionsRequired.add(IndexAction.NAME);
                        break;
                    case INDEX:
                        additionalPermissionsRequired.add(IndexAction.NAME);
                        break;
                    case DELETE:
                        additionalPermissionsRequired.add(DeleteAction.NAME);
                        break;
                    case UPDATE:
                        additionalPermissionsRequired.add(UpdateAction.NAME);
                        break;
                }
            }
        }

        if (request instanceof IndicesAliasesRequest) {
            IndicesAliasesRequest bsr = (IndicesAliasesRequest) request;
            for (IndicesAliasesRequest.AliasActions bir : bsr.getAliasActions()) {
                switch (bir.actionType()) {
                    case REMOVE_INDEX:
                        additionalPermissionsRequired.add(DeleteIndexAction.NAME);
                        break;
                    default:
                        break;
                }
            }
        }

        if (request instanceof CreateIndexRequest) {
            CreateIndexRequest cir = (CreateIndexRequest) request;
            if (cir.aliases() != null && !cir.aliases().isEmpty()) {
                additionalPermissionsRequired.add(IndicesAliasesAction.NAME);
            }
        }

        if (request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
            additionalPermissionsRequired.addAll(ConfigConstants.SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES);
        }

        ImmutableSet<String> result = additionalPermissionsRequired.build();

        if (result.size() > 1) {
            traceAction("Additional permissions required: {}", result);
        }

        if (log.isDebugEnabled() && result.size() > 1) {
            log.debug("Additional permissions required: {}", result);
        }

        return result;
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

        return ((IndicesRequest) request).indicesOptions().allowNoIndices();
    }

    boolean containsPattern(IndicesRequest indicesRequest) {
        String [] indices = indicesRequest.indices();

        if (indices == null || indices.length == 0 || (indices.length == 1 && (Metadata.ALL.equals(indices[0]) || Regex.isMatchAllPattern(indices[0])))) {
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
