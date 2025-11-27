/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesAction;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
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
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.termvectors.MultiTermVectorsAction;
import org.opensearch.action.update.UpdateAction;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.SubjectBasedActionPrivileges;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.OpenSearchSecurityPlugin.traceAction;

/**
 * The current implementation for action privilege evaluation.
 * <p>
 * Moved from https://github.com/opensearch-project/security/blob/062ea716d10240cc50d01735f457523a61393a59/src/main/java/org/opensearch/security/privileges/PrivilegesEvaluator.java
 */
public class PrivilegesEvaluatorImpl implements PrivilegesEvaluator {

    static final WildcardMatcher DNFOF_MATCHER = WildcardMatcher.from(
        ImmutableList.of(
            "indices:data/read/*",
            "indices:admin/mappings/fields/get*",
            "indices:admin/shards/search_shards",
            "indices:admin/resolve/index",
            "indices:monitor/settings/get",
            "indices:monitor/stats",
            "indices:admin/aliases/get"
        )
    );

    private static final WildcardMatcher ACTION_MATCHER = WildcardMatcher.from("indices:data/read/*search*");

    private static final IndicesOptions ALLOW_EMPTY = IndicesOptions.fromOptions(true, true, false, false);

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final Supplier<ClusterState> clusterStateSupplier;

    private final IndexNameExpressionResolver resolver;

    private final AuditLog auditLog;
    private final ThreadContext threadContext;
    private final ThreadPool threadPool;

    private PrivilegesInterceptor privilegesInterceptor;

    private final boolean checkSnapshotRestoreWritePrivileges;

    private final IndexResolverReplacer irr;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final SystemIndexAccessEvaluator systemIndexAccessEvaluator;
    private final ProtectedIndexAccessEvaluator protectedIndexAccessEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;
    private final PitPrivilegesEvaluator pitPrivilegesEvaluator;
    private final Settings settings;
    private final AtomicReference<RoleBasedActionPrivileges> actionPrivileges = new AtomicReference<>();
    private final ImmutableMap<String, ActionPrivileges> pluginIdToActionPrivileges;
    private final RoleMapper roleMapper;

    private volatile boolean dnfofEnabled = false;
    private volatile boolean dnfofForEmptyResultsEnabled = false;
    private volatile String filteredAliasMode = null;

    public PrivilegesEvaluatorImpl(
        final ClusterService clusterService,
        Supplier<ClusterState> clusterStateSupplier,
        RoleMapper roleMapper,
        ThreadPool threadPool,
        final ThreadContext threadContext,
        final IndexNameExpressionResolver resolver,
        AuditLog auditLog,
        final Settings settings,
        final PrivilegesInterceptor privilegesInterceptor,
        final IndexResolverReplacer irr,
        FlattenedActionGroups actionGroups,
        FlattenedActionGroups staticActionGroups,
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
        ConfigV7 generalConfiguration,
        Map<String, RoleV7> pluginIdToRolePrivileges
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

        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(
            ConfigConstants.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
            ConfigConstants.SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES
        );

        Supplier<Boolean> isLocalNodeElectedClusterManager = clusterService != null
            ? () -> clusterService.state().nodes().isLocalNodeElectedClusterManager()
            : () -> false;

        this.irr = irr;
        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, auditLog, isLocalNodeElectedClusterManager);
        systemIndexAccessEvaluator = new SystemIndexAccessEvaluator(settings, auditLog, irr);
        protectedIndexAccessEvaluator = new ProtectedIndexAccessEvaluator(settings, auditLog);
        termsAggregationEvaluator = new TermsAggregationEvaluator();
        pitPrivilegesEvaluator = new PitPrivilegesEvaluator();

        this.pluginIdToActionPrivileges = createActionPrivileges(pluginIdToRolePrivileges, staticActionGroups);
        this.updateConfiguration(actionGroups, rolesConfiguration, generalConfiguration);
    }

    @Override
    public PrivilegesEvaluatorType type() {
        return PrivilegesEvaluatorType.STANDARD;
    }

    @Override
    public void updateConfiguration(
        FlattenedActionGroups flattenedActionGroups,
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration,
        ConfigV7 generalConfiguration
    ) {
        this.dnfofEnabled = isDnfofEnabled(generalConfiguration);
        this.dnfofForEmptyResultsEnabled = isDnfofEmptyEnabled(generalConfiguration);
        this.filteredAliasMode = getFilteredAliasMode(generalConfiguration);

        try {
            RoleBasedActionPrivileges actionPrivileges = new RoleBasedActionPrivileges(rolesConfiguration, flattenedActionGroups, settings);
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
    public PrivilegesEvaluationContext createContext(User user, String action) {
        return createContext(user, action, null, null, null);
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
            actionPrivileges = this.pluginIdToActionPrivileges.getOrDefault(user.getName(), ActionPrivileges.EMPTY);
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
            irr,
            resolver,
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

        PrivilegesEvaluatorResponse presponse;

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {}", user);
            log.debug("Action: {} ({})", action0, request.getClass().getSimpleName());
            log.debug("Mapped roles: {}", mappedRoles.toString());
        }

        ActionPrivileges actionPrivileges = context.getActionPrivileges();

        if (request instanceof BulkRequest && (Strings.isNullOrEmpty(user.getRequestedTenant()))) {
            // Shortcut for bulk actions. The details are checked on the lower level of the BulkShardRequests (Action
            // indices:data/write/bulk[s]).
            // This shortcut is only possible if the default tenant is selected, as we might need to rewrite the request for non-default
            // tenants.
            // No further access check for the default tenant is necessary, as access will be also checked on the TransportShardBulkAction
            // level.

            presponse = actionPrivileges.hasClusterPrivilege(context, action0);

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

        final Resolved requestedResolved = context.getResolvedRequest();

        log.debug("RequestedResolved : {}", requestedResolved);

        // check snapshot/restore requests
        // NOTE: Has to go first as restore request could be for protected and/or system indices and the request may
        // fail with 403 if system index or protected index evaluators are triggered first
        presponse = snapshotRestoreEvaluator.evaluate(request, task, action0);
        if (presponse != null) {
            return presponse;
        }

        // System index access
        presponse = systemIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, context, actionPrivileges, user);
        if (presponse != null) {
            return presponse;
        }

        // Protected index access
        presponse = protectedIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, mappedRoles);
        if (presponse != null) {
            return presponse;
        }

        // check access for point in time requests
        presponse = pitPrivilegesEvaluator.evaluate(request, context, actionPrivileges, action0, irr);
        if (presponse != null) {
            return presponse;
        }

        final boolean dnfofEnabled = this.dnfofEnabled;

        log.trace("dnfof enabled? {}", dnfofEnabled);

        final boolean serviceAccountUser = user.isServiceAccount();
        if (isClusterPerm(action0)) {
            if (serviceAccountUser) {
                log.info("{} is a service account which doesn't have access to cluster level permission: {}", user, action0);
                return PrivilegesEvaluatorResponse.insufficient(action0);
            }

            presponse = actionPrivileges.hasClusterPrivilege(context, action0);

            if (!presponse.isAllowed()) {
                log.info(
                    "No cluster-level perm match for {} {} [Action [{}]] [RolesChecked {}]. No permissions for {}",
                    user,
                    requestedResolved,
                    action0,
                    mappedRoles,
                    presponse.getMissingPrivileges()
                );
                return presponse;
            } else {

                if (request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
                    log.debug("Normally allowed but we need to apply some extra checks for a restore request.");

                } else {
                    if (privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

                        final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
                            request,
                            action0,
                            user,
                            requestedResolved,
                            context
                        );

                        log.debug("Result from privileges interceptor for cluster perm: {}", replaceResult);

                        if (!replaceResult.continueEvaluation) {
                            if (replaceResult.accessDenied) {
                                auditLog.logMissingPrivileges(action0, request, task);
                            } else {
                                return PrivilegesEvaluatorResponse.ok().with(replaceResult.createIndexRequestBuilder);
                            }
                        }
                    }

                    log.debug("Allowed because we have cluster permissions for {}", action0);

                    return PrivilegesEvaluatorResponse.ok();
                }
            }
        }

        if (checkDocAllowListHeader(user, action0, request)) {
            return PrivilegesEvaluatorResponse.ok();
        }

        // term aggregations
        presponse = termsAggregationEvaluator.evaluate(requestedResolved, request, context, actionPrivileges);
        if (presponse != null) {
            return presponse;
        }

        ImmutableSet<String> allIndexPermsRequired = evaluateAdditionalIndexPermissions(request, action0);

        log.debug("Requested {}", allIndexPermsRequired);
        log.debug("Requested resolved index types: {}", requestedResolved);
        log.debug("Security roles: {}", mappedRoles);

        // TODO exclude Security index

        if (privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

            final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
                request,
                action0,
                user,
                requestedResolved,
                context
            );

            log.debug("Result from privileges interceptor: {}", replaceResult);

            if (!replaceResult.continueEvaluation) {
                if (replaceResult.accessDenied) {
                    auditLog.logMissingPrivileges(action0, request, task);
                    return PrivilegesEvaluatorResponse.insufficient(action0);
                } else {
                    return PrivilegesEvaluatorResponse.ok().with(replaceResult.createIndexRequestBuilder);
                }
            }
        }

        boolean dnfofPossible = dnfofEnabled && DNFOF_MATCHER.test(action0);

        presponse = actionPrivileges.hasIndexPrivilege(context, allIndexPermsRequired, requestedResolved);

        if (presponse.isPartiallyOk()) {
            if (dnfofPossible) {
                if (irr.replace(request, true, presponse.getAvailableIndices())) {
                    return PrivilegesEvaluatorResponse.ok();
                }
            }
        } else if (!presponse.isAllowed()) {
            if (dnfofPossible && this.dnfofForEmptyResultsEnabled && request instanceof IndicesRequest.Replaceable) {
                ((IndicesRequest.Replaceable) request).indices(new String[0]);

                if (request instanceof SearchRequest) {
                    ((SearchRequest) request).indicesOptions(ALLOW_EMPTY);
                } else if (request instanceof ClusterSearchShardsRequest) {
                    ((ClusterSearchShardsRequest) request).indicesOptions(ALLOW_EMPTY);
                } else if (request instanceof GetFieldMappingsRequest) {
                    ((GetFieldMappingsRequest) request).indicesOptions(ALLOW_EMPTY);
                }

                return PrivilegesEvaluatorResponse.ok();
            }
        }

        if (presponse.isAllowed()) {
            if (checkFilteredAliases(requestedResolved, action0, isDebugEnabled)) {
                return PrivilegesEvaluatorResponse.insufficient(action0);
            }

            log.debug("Allowed because we have all indices permissions for {}", action0);

        } else {
            log.info(
                "No {}-level perm match for {} {}: {} [Action [{}]] [RolesChecked {}]",
                "index",
                user,
                requestedResolved,
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
    public boolean notFailOnForbiddenEnabled() {
        return dnfofEnabled;
    }

    private ImmutableSet<String> evaluateAdditionalIndexPermissions(final ActionRequest request, final String originalAction) {
        ImmutableSet.Builder<String> additionalPermissionsRequired = ImmutableSet.builder();

        if (!isClusterPerm(originalAction)) {
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
            for (AliasActions bir : bsr.getAliasActions()) {
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
            log.debug("Additional permissions required: {}", result);
        }

        return result;
    }

    @Override
    public boolean isClusterPermission(String action) {
        return isClusterPerm(action);
    }

    public static boolean isClusterPerm(String action0) {
        return (action0.startsWith("cluster:")
            || action0.startsWith("indices:admin/template/")
            || action0.startsWith("indices:admin/index_template/")
            || action0.startsWith(SearchScrollAction.NAME)
            || (action0.equals(BulkAction.NAME))
            || (action0.equals(MultiGetAction.NAME))
            || (action0.startsWith(MultiSearchAction.NAME))
            || (action0.equals(MultiTermVectorsAction.NAME))
            || (action0.equals(ReindexAction.NAME))
            || (action0.equals(RenderSearchTemplateAction.NAME)));
    }

    private boolean checkFilteredAliases(Resolved requestedResolved, String action, boolean isDebugEnabled) {
        final String faMode = this.filteredAliasMode;// getConfigSettings().dynamic.filtered_alias_mode;

        if (!"disallow".equals(faMode)) {
            return false;
        }

        if (!ACTION_MATCHER.test(action)) {
            return false;
        }

        Iterable<IndexMetadata> indexMetaDataCollection;

        if (requestedResolved.isLocalAll()) {
            indexMetaDataCollection = new Iterable<IndexMetadata>() {
                @Override
                public Iterator<IndexMetadata> iterator() {
                    return clusterStateSupplier.get().getMetadata().getIndices().values().iterator();
                }
            };
        } else {
            Set<IndexMetadata> indexMetaDataSet = new HashSet<>(requestedResolved.getAllIndices().size());

            for (String requestAliasOrIndex : requestedResolved.getAllIndices()) {
                IndexMetadata indexMetaData = clusterStateSupplier.get().getMetadata().getIndices().get(requestAliasOrIndex);
                if (indexMetaData == null) {
                    log.debug("{} does not exist in cluster metadata", requestAliasOrIndex);
                    continue;
                }

                indexMetaDataSet.add(indexMetaData);
            }

            indexMetaDataCollection = indexMetaDataSet;
        }
        // check filtered aliases
        for (IndexMetadata indexMetaData : indexMetaDataCollection) {

            final List<AliasMetadata> filteredAliases = new ArrayList<AliasMetadata>();

            final Map<String, AliasMetadata> aliases = indexMetaData.getAliases();

            if (aliases != null && aliases.size() > 0) {
                log.debug("Aliases for {}: {}", indexMetaData.getIndex().getName(), aliases);

                final Iterator<String> it = aliases.keySet().iterator();
                while (it.hasNext()) {
                    final String alias = it.next();
                    final AliasMetadata aliasMetadata = aliases.get(alias);

                    if (aliasMetadata != null && aliasMetadata.filteringRequired()) {
                        filteredAliases.add(aliasMetadata);
                        log.debug("{} is a filtered alias {}", alias, aliasMetadata.getFilter());

                    } else {
                        log.debug("{} is not an alias or does not have a filter", alias);

                    }
                }
            }

            if (filteredAliases.size() > 1 && ACTION_MATCHER.test(action)) {
                log.error(
                    "More than one ({}) filtered alias found for same index ({}). This is currently not supported. Aliases: {}",
                    filteredAliases.size(),
                    indexMetaData.getIndex().getName(),
                    toString(filteredAliases)
                );
                return true;
            }
        } // end-for

        return false;
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
                log.debug("Request {} is allowed by {}", request, documentAllowList);
                return true;
            } else {
                return false;
            }

        } catch (Exception e) {
            log.error("Error while handling document allow list: {}", docAllowListHeader, e);
            return false;
        }
    }

    private List<String> toString(List<AliasMetadata> aliases) {
        if (aliases == null || aliases.size() == 0) {
            return Collections.emptyList();
        }

        final List<String> ret = new ArrayList<>(aliases.size());

        for (final AliasMetadata amd : aliases) {
            if (amd != null) {
                ret.add(amd.alias());
            }
        }

        return Collections.unmodifiableList(ret);
    }

    private static ImmutableMap<String, ActionPrivileges> createActionPrivileges(
        Map<String, RoleV7> pluginIdToRolePrivileges,
        FlattenedActionGroups staticActionGroups
    ) {
        Map<String, SubjectBasedActionPrivileges> result = new HashMap<>(pluginIdToRolePrivileges.size());

        for (Map.Entry<String, RoleV7> entry : pluginIdToRolePrivileges.entrySet()) {
            result.put(entry.getKey(), new SubjectBasedActionPrivileges(entry.getValue(), staticActionGroups));
        }

        return ImmutableMap.copyOf(result);
    }

    private static boolean isDnfofEnabled(ConfigV7 generalConfiguration) {
        return generalConfiguration.dynamic != null && generalConfiguration.dynamic.do_not_fail_on_forbidden;
    }

    private static boolean isDnfofEmptyEnabled(ConfigV7 generalConfiguration) {
        return generalConfiguration.dynamic != null && generalConfiguration.dynamic.do_not_fail_on_forbidden_empty;
    }

    private static String getFilteredAliasMode(ConfigV7 generalConfiguration) {
        return generalConfiguration.dynamic != null ? generalConfiguration.dynamic.filtered_alias_mode : "none";
    }
}
