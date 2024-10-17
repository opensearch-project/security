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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableList;
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
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.script.mustache.RenderSearchTemplateAction;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.DashboardSignInOption;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;

import org.greenrobot.eventbus.Subscribe;

import static org.opensearch.security.OpenSearchSecurityPlugin.traceAction;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT;

public class PrivilegesEvaluator {

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
    private ThreadContext threadContext;

    private PrivilegesInterceptor privilegesInterceptor;

    private final boolean checkSnapshotRestoreWritePrivileges;

    private final ClusterInfoHolder clusterInfoHolder;
    private ConfigModel configModel;
    private final IndexResolverReplacer irr;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final SystemIndexAccessEvaluator systemIndexAccessEvaluator;
    private final ProtectedIndexAccessEvaluator protectedIndexAccessEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;
    private final PitPrivilegesEvaluator pitPrivilegesEvaluator;
    private DynamicConfigModel dcm;
    private final NamedXContentRegistry namedXContentRegistry;
    private final Settings settings;
    private final AtomicReference<ActionPrivileges> actionPrivileges = new AtomicReference<>();

    public PrivilegesEvaluator(
        final ClusterService clusterService,
        Supplier<ClusterState> clusterStateSupplier,
        ThreadPool threadPool,
        final ThreadContext threadContext,
        final ConfigurationRepository configurationRepository,
        final IndexNameExpressionResolver resolver,
        AuditLog auditLog,
        final Settings settings,
        final PrivilegesInterceptor privilegesInterceptor,
        final ClusterInfoHolder clusterInfoHolder,
        final IndexResolverReplacer irr,
        NamedXContentRegistry namedXContentRegistry
    ) {

        super();
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadContext;
        this.privilegesInterceptor = privilegesInterceptor;
        this.clusterStateSupplier = clusterStateSupplier;
        this.settings = settings;

        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(
            ConfigConstants.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
            ConfigConstants.SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES
        );

        this.clusterInfoHolder = clusterInfoHolder;
        this.irr = irr;
        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, auditLog);
        systemIndexAccessEvaluator = new SystemIndexAccessEvaluator(settings, auditLog, irr);
        protectedIndexAccessEvaluator = new ProtectedIndexAccessEvaluator(settings, auditLog);
        termsAggregationEvaluator = new TermsAggregationEvaluator();
        pitPrivilegesEvaluator = new PitPrivilegesEvaluator();
        this.namedXContentRegistry = namedXContentRegistry;

        if (configurationRepository != null) {
            configurationRepository.subscribeOnChange(configMap -> {
                try {
                    SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfiguration = configurationRepository.getConfiguration(
                        CType.ACTIONGROUPS
                    );
                    SecurityDynamicConfiguration<RoleV7> rolesConfiguration = configurationRepository.getConfiguration(CType.ROLES);

                    this.updateConfiguration(actionGroupsConfiguration, rolesConfiguration);
                } catch (Exception e) {
                    log.error("Error while updating ActionPrivileges object with {}", configMap, e);
                }
            });
        }

        if (clusterService != null) {
            clusterService.addListener(event -> {
                ActionPrivileges actionPrivileges = PrivilegesEvaluator.this.actionPrivileges.get();
                if (actionPrivileges != null) {
                    actionPrivileges.updateStatefulIndexPrivilegesAsync(clusterService, threadPool);
                }
            });
        }

    }

    void updateConfiguration(
        SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfiguration,
        SecurityDynamicConfiguration<RoleV7> rolesConfiguration
    ) {
        if (rolesConfiguration != null) {
            SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsWithStatics = actionGroupsConfiguration != null
                ? DynamicConfigFactory.addStatics(actionGroupsConfiguration.clone())
                : DynamicConfigFactory.addStatics(SecurityDynamicConfiguration.empty(CType.ACTIONGROUPS));
            FlattenedActionGroups flattenedActionGroups = new FlattenedActionGroups(actionGroupsWithStatics);
            ActionPrivileges actionPrivileges = new ActionPrivileges(
                DynamicConfigFactory.addStatics(rolesConfiguration.clone()),
                flattenedActionGroups,
                () -> clusterStateSupplier.get().metadata().getIndicesLookup(),
                settings
            );
            Metadata metadata = clusterStateSupplier.get().metadata();
            actionPrivileges.updateStatefulIndexPrivileges(metadata.getIndicesLookup(), metadata.version());
            ActionPrivileges oldInstance = this.actionPrivileges.getAndSet(actionPrivileges);

            if (oldInstance != null) {
                oldInstance.shutdown();
            }
        }
    }

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
    }

    public ActionPrivileges getActionPrivileges() {
        return this.actionPrivileges.get();
    }

    public boolean hasRestAdminPermissions(final User user, final TransportAddress remoteAddress, final String permission) {
        PrivilegesEvaluationContext context = createContext(user, permission);
        return this.actionPrivileges.get().hasExplicitClusterPrivilege(context, permission).isAllowed();
    }

    public boolean isInitialized() {
        return configModel != null && dcm != null && actionPrivileges.get() != null;
    }

    private void setUserInfoInThreadContext(User user) {
        if (threadContext.getTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT) == null) {
            StringJoiner joiner = new StringJoiner("|");
            joiner.add(user.getName());
            joiner.add(String.join(",", user.getRoles()));
            joiner.add(String.join(",", user.getSecurityRoles()));
            String requestedTenant = user.getRequestedTenant();
            if (!Strings.isNullOrEmpty(requestedTenant)) {
                joiner.add(requestedTenant);
            }
            threadContext.putTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT, joiner.toString());
        }
    }

    public PrivilegesEvaluationContext createContext(User user, String action) {
        return createContext(user, action, null, null, null);
    }

    public PrivilegesEvaluationContext createContext(
        User user,
        String action0,
        ActionRequest request,
        Task task,
        Set<String> injectedRoles
    ) {
        if (!isInitialized()) {
            throw new OpenSearchSecurityException("OpenSearch Security is not initialized.");
        }

        TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        ImmutableSet<String> mappedRoles = ImmutableSet.copyOf((injectedRoles == null) ? mapRoles(user, caller) : injectedRoles);

        return new PrivilegesEvaluationContext(user, mappedRoles, action0, request, task, irr, resolver, clusterStateSupplier);
    }

    public PrivilegesEvaluatorResponse evaluate(PrivilegesEvaluationContext context) {

        if (!isInitialized()) {
            throw new OpenSearchSecurityException("OpenSearch Security is not initialized.");
        }

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

        PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();

        final String injectedRolesValidationString = threadContext.getTransient(
            ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION
        );
        if (injectedRolesValidationString != null) {
            HashSet<String> injectedRolesValidationSet = new HashSet<>(Arrays.asList(injectedRolesValidationString.split(",")));
            if (!mappedRoles.containsAll(injectedRolesValidationSet)) {
                presponse.allowed = false;
                presponse.missingSecurityRoles.addAll(injectedRolesValidationSet);
                log.info("Roles {} are not mapped to the user {}", injectedRolesValidationSet, user);
                return presponse;
            }
            mappedRoles = ImmutableSet.copyOf(injectedRolesValidationSet);
            context.setMappedRoles(mappedRoles);
        }

        // Add the security roles for this user so that they can be used for DLS parameter substitution.
        user.addSecurityRoles(mappedRoles);
        setUserInfoInThreadContext(user);

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {}", user);
            log.debug("Action: {} ({})", action0, request.getClass().getSimpleName());
            log.debug("Mapped roles: {}", mappedRoles.toString());
        }

        ActionPrivileges actionPrivileges = this.actionPrivileges.get();
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

            presponse = actionPrivileges.hasClusterPrivilege(context, action0);

            if (!presponse.allowed) {
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

        if (isDebugEnabled) {
            log.debug("RequestedResolved : {}", requestedResolved);
        }

        // check snapshot/restore requests
        if (snapshotRestoreEvaluator.evaluate(request, task, action0, clusterInfoHolder, presponse).isComplete()) {
            return presponse;
        }

        // Security index access
        if (systemIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, presponse, context, actionPrivileges, user)
            .isComplete()) {
            return presponse;
        }

        // Protected index access
        if (protectedIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, presponse, mappedRoles).isComplete()) {
            return presponse;
        }

        // check access for point in time requests
        if (pitPrivilegesEvaluator.evaluate(request, context, actionPrivileges, action0, presponse, irr).isComplete()) {
            return presponse;
        }

        final boolean dnfofEnabled = dcm.isDnfofEnabled();

        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("dnfof enabled? {}", dnfofEnabled);
        }

        final boolean serviceAccountUser = user.isServiceAccount();
        if (isClusterPerm(action0)) {
            if (serviceAccountUser) {
                log.info("{} is a service account which doesn't have access to cluster level permission: {}", user, action0);
                return PrivilegesEvaluatorResponse.insufficient(action0, context);
            }

            presponse = actionPrivileges.hasClusterPrivilege(context, action0);

            if (!presponse.allowed) {
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
                    if (isDebugEnabled) {
                        log.debug("Normally allowed but we need to apply some extra checks for a restore request.");
                    }
                } else {
                    if (privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

                        final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
                            request,
                            action0,
                            user,
                            dcm,
                            requestedResolved,
                            mapTenants(user, mappedRoles)
                        );

                        if (isDebugEnabled) {
                            log.debug("Result from privileges interceptor for cluster perm: {}", replaceResult);
                        }

                        if (!replaceResult.continueEvaluation) {
                            if (replaceResult.accessDenied) {
                                auditLog.logMissingPrivileges(action0, request, task);
                            } else {
                                presponse.allowed = true;
                                presponse.createIndexRequestBuilder = replaceResult.createIndexRequestBuilder;
                            }
                            return presponse;
                        }
                    }

                    if (isDebugEnabled) {
                        log.debug("Allowed because we have cluster permissions for {}", action0);
                    }
                    presponse.allowed = true;
                    return presponse;
                }
            }
        }

        if (checkDocAllowListHeader(user, action0, request)) {
            presponse.allowed = true;
            return presponse;
        }

        // term aggregations
        if (termsAggregationEvaluator.evaluate(requestedResolved, request, context, actionPrivileges, presponse).isComplete()) {
            return presponse;
        }

        ImmutableSet<String> allIndexPermsRequired = evaluateAdditionalIndexPermissions(request, action0);

        if (isDebugEnabled) {
            log.debug(
                "Requested {} from {}",
                allIndexPermsRequired,
                threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS)
            );
        }

        if (isDebugEnabled) {
            log.debug("Requested resolved index types: {}", requestedResolved);
            log.debug("Security roles: {}", mappedRoles);
        }

        // TODO exclude Security index

        if (privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

            final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(
                request,
                action0,
                user,
                dcm,
                requestedResolved,
                mapTenants(user, mappedRoles)
            );

            if (isDebugEnabled) {
                log.debug("Result from privileges interceptor: {}", replaceResult);
            }

            if (!replaceResult.continueEvaluation) {
                if (replaceResult.accessDenied) {
                    auditLog.logMissingPrivileges(action0, request, task);
                    return PrivilegesEvaluatorResponse.insufficient(action0, context);
                } else {
                    presponse.allowed = true;
                    presponse.createIndexRequestBuilder = replaceResult.createIndexRequestBuilder;
                    return presponse;
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
            if (dnfofPossible && dcm.isDnfofForEmptyResultsEnabled() && request instanceof IndicesRequest.Replaceable) {
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
                presponse.allowed = false;
                return presponse;
            }

            if (isDebugEnabled) {
                log.debug("Allowed because we have all indices permissions for {}", action0);
            }
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

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

    public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {
        return this.configModel.mapTenants(user, roles);
    }

    public Set<String> getAllConfiguredTenantNames() {

        return configModel.getAllConfiguredTenantNames();
    }

    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class && dcm.isDashboardsMultitenancyEnabled();
    }

    public boolean privateTenantEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class && dcm.isDashboardsPrivateTenantEnabled();
    }

    public String dashboardsDefaultTenant() {
        return dcm.getDashboardsDefaultTenant();
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class && dcm.isDnfofEnabled();
    }

    public String dashboardsIndex() {
        return dcm.getDashboardsIndexname();
    }

    public String dashboardsServerUsername() {
        return dcm.getDashboardsServerUsername();
    }

    public String dashboardsOpenSearchRole() {
        return dcm.getDashboardsOpenSearchRole();
    }

    public List<DashboardSignInOption> getSignInOptions() {
        return dcm.getSignInOptions();
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
        }

        if (log.isDebugEnabled() && result.size() > 1) {
            log.debug("Additional permissions required: {}", result);
        }

        return result;
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

    @SuppressWarnings("unchecked")
    private boolean checkFilteredAliases(Resolved requestedResolved, String action, boolean isDebugEnabled) {
        final String faMode = dcm.getFilteredAliasMode();// getConfigSettings().dynamic.filtered_alias_mode;

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
                    if (isDebugEnabled) {
                        log.debug("{} does not exist in cluster metadata", requestAliasOrIndex);
                    }
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
                if (isDebugEnabled) {
                    log.debug("Aliases for {}: {}", indexMetaData.getIndex().getName(), aliases);
                }

                final Iterator<String> it = aliases.keySet().iterator();
                while (it.hasNext()) {
                    final String alias = it.next();
                    final AliasMetadata aliasMetadata = aliases.get(alias);

                    if (aliasMetadata != null && aliasMetadata.filteringRequired()) {
                        filteredAliases.add(aliasMetadata);
                        if (isDebugEnabled) {
                            log.debug("{} is a filtered alias {}", alias, aliasMetadata.getFilter());
                        }
                    } else {
                        if (isDebugEnabled) {
                            log.debug("{} is not an alias or does not have a filter", alias);
                        }
                    }
                }
            }

            if (filteredAliases.size() > 1 && ACTION_MATCHER.test(action)) {
                // TODO add queries as dls queries (works only if dls module is installed)
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
}
