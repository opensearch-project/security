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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesAction;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.AutoCreateAction;
import org.elasticsearch.action.admin.indices.create.CreateIndexAction;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.admin.indices.mapping.get.GetFieldMappingsRequest;
import org.elasticsearch.action.admin.indices.mapping.put.AutoPutMappingAction;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingAction;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.get.MultiGetAction;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.search.MultiSearchAction;
import org.elasticsearch.action.search.SearchAction;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchScrollAction;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.termvectors.MultiTermVectorsAction;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.reindex.ReindexAction;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.greenrobot.eventbus.Subscribe;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.User;

import com.google.common.collect.Sets;

import static com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin.traceAction;
import static com.amazon.opendistroforelasticsearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT;

public class PrivilegesEvaluator {

    private static final WildcardMatcher ACTION_MATCHER = WildcardMatcher.from("indices:data/read/*search*");
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ClusterService clusterService;

    private final IndexNameExpressionResolver resolver;

    private final AuditLog auditLog;
    private ThreadContext threadContext;

    private PrivilegesInterceptor privilegesInterceptor;

    private final boolean checkSnapshotRestoreWritePrivileges;

    private final ClusterInfoHolder clusterInfoHolder;
    private ConfigModel configModel;
    private final IndexResolverReplacer irr;
    private final SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private final OpenDistroSecurityIndexAccessEvaluator securityIndexAccessEvaluator;
    private final OpenDistroProtectedIndexAccessEvaluator protectedIndexAccessEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;

    private final DlsFlsEvaluator dlsFlsEvaluator;

    private final boolean advancedModulesEnabled;
    private DynamicConfigModel dcm;

    public PrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool,
                               final ConfigurationRepository configurationRepository, final IndexNameExpressionResolver resolver,
                               AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor, final ClusterInfoHolder clusterInfoHolder,
                               final IndexResolverReplacer irr, boolean advancedModulesEnabled) {

        super();
        this.clusterService = clusterService;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.privilegesInterceptor = privilegesInterceptor;


        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);

        this.clusterInfoHolder = clusterInfoHolder;
        this.irr = irr;
        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, auditLog);
        securityIndexAccessEvaluator = new OpenDistroSecurityIndexAccessEvaluator(settings, auditLog, irr);
        protectedIndexAccessEvaluator = new OpenDistroProtectedIndexAccessEvaluator(settings, auditLog);
        dlsFlsEvaluator = new DlsFlsEvaluator(settings, threadPool);
        termsAggregationEvaluator = new TermsAggregationEvaluator();
        this.advancedModulesEnabled = advancedModulesEnabled;
    }

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
    }

    private SecurityRoles getSecurityRoles(Set<String> roles) {
        return configModel.getSecurityRoles().filter(roles);
    }

    public boolean isInitialized() {
        return configModel !=null && configModel.getSecurityRoles() != null && dcm != null;
    }

    private void setUserInfoInThreadContext(User user, Set<String> mappedRoles) {
        if (threadContext.getTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT) == null) {
            StringJoiner joiner = new StringJoiner("|");
            joiner.add(user.getName());
            joiner.add(String.join(",", user.getRoles()));
            joiner.add(String.join(",", Sets.union(user.getOpenDistroSecurityRoles(), mappedRoles)));
            String requestedTenant = user.getRequestedTenant();
            if (!Strings.isNullOrEmpty(requestedTenant)) {
                joiner.add(requestedTenant);
            }
            threadContext.putTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT, joiner.toString());
        }
    }

    public PrivilegesEvaluatorResponse evaluate(final User user, String action0, final ActionRequest request,
                                                Task task, final Set<String> injectedRoles) {

        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Open Distro Security is not initialized.");
        }

        if(action0.startsWith("internal:indices/admin/upgrade")) {
            action0 = "indices:admin/upgrade";
        }

        if (AutoCreateAction.NAME.equals(action0)) {
            action0 = CreateIndexAction.NAME;
        }

        if (AutoPutMappingAction.NAME.equals(action0)) {
            action0 = PutMappingAction.NAME;
        }

        final TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        final Set<String> mappedRoles = (injectedRoles == null) ? mapRoles(user, caller) : injectedRoles;
        final SecurityRoles securityRoles = getSecurityRoles(mappedRoles);

        setUserInfoInThreadContext(user, mappedRoles);

        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();


        if (log.isDebugEnabled()) {
            log.debug("### evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("action: "+action0+" ("+request.getClass().getSimpleName()+")");
            log.debug("mapped roles: {}",mappedRoles.toString());
        }

        if (request instanceof BulkRequest && (Strings.isNullOrEmpty(user.getRequestedTenant()))) {
            // Shortcut for bulk actions. The details are checked on the lower level of the BulkShardRequests (Action indices:data/write/bulk[s]).
            // This shortcut is only possible if the default tenant is selected, as we might need to rewrite the request for non-default tenants.
            // No further access check for the default tenant is necessary, as access will be also checked on the TransportShardBulkAction level.

            if (!securityRoles.impliesClusterPermissionPermission(action0)) {
                presponse.missingPrivileges.add(action0);
                presponse.allowed = false;
                log.info("No cluster-level perm match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}", user, action0,
                        securityRoles.getRoleNames(), presponse.missingPrivileges);
            } else {
                presponse.allowed = true;
            }
            return presponse;
        }

        final Resolved requestedResolved = irr.resolveRequest(request);

        if (log.isDebugEnabled()) {
            log.debug("requestedResolved : {}", requestedResolved );
        }


        // check dlsfls
        if (advancedModulesEnabled
                //&& (action0.startsWith("indices:data/read") || action0.equals(ClusterSearchShardsAction.NAME))
                && dlsFlsEvaluator.evaluate(request, clusterService, resolver, requestedResolved, user, securityRoles, presponse).isComplete()) {
            return presponse;
        }

        // check snapshot/restore requests
        if (snapshotRestoreEvaluator.evaluate(request, task, action0, clusterInfoHolder, presponse).isComplete()) {
            return presponse;
        }

        // Security index access
        if (securityIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, presponse).isComplete()) {
            return presponse;
        }

        // Protected index access
        if (protectedIndexAccessEvaluator.evaluate(request, task, action0, requestedResolved, presponse, securityRoles).isComplete()) {
            return presponse;
        }

        final boolean dnfofEnabled = dcm.isDnfofEnabled();

        if(log.isTraceEnabled()) {
            log.trace("dnfof enabled? {}", dnfofEnabled);
        }


        if (isClusterPerm(action0)) {
            if(!securityRoles.impliesClusterPermissionPermission(action0)) {
                presponse.missingPrivileges.add(action0);
                presponse.allowed = false;
                log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", "cluster" , user, requestedResolved, action0,
                        securityRoles.getRoleNames());
                log.info("No permissions for {}", presponse.missingPrivileges);
                return presponse;
            } else {

                if(request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
                    if(log.isDebugEnabled()) {
                        log.debug("Normally allowed but we need to apply some extra checks for a restore request.");
                    }
                } else {


                    if(privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

                        final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceKibanaIndex(request, action0, user, dcm, requestedResolved,
                                mapTenants(user, mappedRoles));

                        if(log.isDebugEnabled()) {
                            log.debug("Result from privileges interceptor for cluster perm: {}", replaceResult);
                        }

                        if (!replaceResult.continueEvaluation) {
                            if (replaceResult.accessDenied) {
                                auditLog.logMissingPrivileges(action0, request, task);
                            } else {
                                presponse.allowed = true;
                                presponse.request = replaceResult.createIndexRequest;
                            }
                            return presponse;
                        }
                    }

                    if (dnfofEnabled
                            && (action0.startsWith("indices:data/read/"))
                            && !requestedResolved.getAllIndices().isEmpty()
                            ) {

                        if(requestedResolved.getAllIndices().isEmpty()) {
                            presponse.missingPrivileges.clear();
                            presponse.allowed = true;
                            return presponse;
                        }


                        Set<String> reduced = securityRoles.reduce(requestedResolved, user, new String[]{action0}, resolver, clusterService);

                        if(reduced.isEmpty()) {
                            presponse.allowed = false;
                            return presponse;
                        }

                        if(irr.replace(request, true, reduced.toArray(new String[0]))) {
                            presponse.missingPrivileges.clear();
                            presponse.allowed = true;
                            return presponse;
                        }
                    }

                    if(log.isDebugEnabled()) {
                        log.debug("Allowed because we have cluster permissions for "+action0);
                    }
                    presponse.allowed = true;
                    return presponse;
                }


            }
        }

        // term aggregations
        if (termsAggregationEvaluator.evaluate(requestedResolved, request, clusterService, user, securityRoles, resolver, presponse) .isComplete()) {
            return presponse;
        }

        final Set<String> allIndexPermsRequired = evaluateAdditionalIndexPermissions(request, action0);
        final String[] allIndexPermsRequiredA = allIndexPermsRequired.toArray(new String[0]);

        if(log.isDebugEnabled()) {
            log.debug("requested {} from {}", allIndexPermsRequired, caller);
        }

        presponse.missingPrivileges.clear();
        presponse.missingPrivileges.addAll(allIndexPermsRequired);

        if (log.isDebugEnabled()) {
            log.debug("requested resolved indextypes: {}", requestedResolved);
        }

        if (log.isDebugEnabled()) {
            log.debug("sr: {}", securityRoles.getRoleNames());
        }


        //TODO exclude Security index

        if(privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

            final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceKibanaIndex(request, action0, user, dcm, requestedResolved, mapTenants(user, mappedRoles));

            if(log.isDebugEnabled()) {
                log.debug("Result from privileges interceptor: {}", replaceResult);
            }

            if (!replaceResult.continueEvaluation) {
                if (replaceResult.accessDenied) {
                    auditLog.logMissingPrivileges(action0, request, task);
                } else {
                    presponse.allowed = true;
                    presponse.request = replaceResult.createIndexRequest;
                }
                return presponse;
            }
        }

        if (dnfofEnabled
                && (action0.startsWith("indices:data/read/")
                || action0.startsWith("indices:admin/mappings/fields/get")
                || action0.equals("indices:admin/shards/search_shards"))) {

            if(requestedResolved.getAllIndices().isEmpty()) {
                presponse.missingPrivileges.clear();
                presponse.allowed = true;
                return presponse;
            }


            Set<String> reduced = securityRoles.reduce(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

            if(reduced.isEmpty()) {
                if(dcm.isDnfofForEmptyResultsEnabled()) {
                    if(request instanceof SearchRequest) {
                        ((SearchRequest) request).indices(new String[0]);
                        ((SearchRequest) request).indicesOptions(IndicesOptions.fromOptions(true, true, false, false));
                        presponse.missingPrivileges.clear();
                        presponse.allowed = true;
                        return presponse;
                    }

                    if(request instanceof ClusterSearchShardsRequest) {
                        ((ClusterSearchShardsRequest) request).indices(new String[0]);
                        ((ClusterSearchShardsRequest) request).indicesOptions(IndicesOptions.fromOptions(true, true, false, false));
                        presponse.missingPrivileges.clear();
                        presponse.allowed = true;
                        return presponse;
                    }

                    if(request instanceof GetFieldMappingsRequest) {
                        ((GetFieldMappingsRequest) request).indices(new String[0]);
                        ((GetFieldMappingsRequest) request).indicesOptions(IndicesOptions.fromOptions(true, true, false, false));
                        presponse.missingPrivileges.clear();
                        presponse.allowed = true;
                        return presponse;
                    }
                }
                presponse.allowed = false;
                return presponse;
            }


            if(irr.replace(request, true, reduced.toArray(new String[0]))) {
                presponse.missingPrivileges.clear();
                presponse.allowed = true;
                return presponse;
            }
        }


        //not bulk, mget, etc request here
        boolean permGiven = false;

        if (log.isDebugEnabled()) {
            log.debug("sr2: {}", securityRoles.getRoleNames());
        }

        if (dcm.isMultiRolespanEnabled()) {
            permGiven = securityRoles.impliesTypePermGlobal(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);
        }  else {
            permGiven = securityRoles.get(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

        }

         if (!permGiven) {
            log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", "index" , user, requestedResolved, action0,
                    securityRoles.getRoleNames());
            log.info("No permissions for {}", presponse.missingPrivileges);
        } else {

            if(checkFilteredAliases(requestedResolved.getAllIndices(), action0)) {
                presponse.allowed=false;
                return presponse;
            }

            if(log.isDebugEnabled()) {
                log.debug("Allowed because we have all indices permissions for "+action0);
            }
        }

        presponse.allowed = permGiven;
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
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && dcm.isKibanaMultitenancyEnabled();
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && dcm.isDnfofEnabled();
    }

    public String kibanaIndex() {
        return dcm.getKibanaIndexname();
    }

    public String kibanaServerUsername() {
        return dcm.getKibanaServerUsername();
    }

    public String kibanaOpendistroRole() {
        return dcm.getKibanaOpendistroRole();
    }

    private Set<String> evaluateAdditionalIndexPermissions(final ActionRequest request, final String originalAction) {
      //--- check inner bulk requests
        final Set<String> additionalPermissionsRequired = new HashSet<>();

        if(!isClusterPerm(originalAction)) {
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
            additionalPermissionsRequired.addAll(ConfigConstants.OPENDISTRO_SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES);
        }

        if (additionalPermissionsRequired.size() > 1) {
            traceAction("Additional permissions required: {}", additionalPermissionsRequired);
        }

        if(log.isDebugEnabled() && additionalPermissionsRequired.size() > 1) {
            log.debug("Additional permissions required: "+additionalPermissionsRequired);
        }

        return Collections.unmodifiableSet(additionalPermissionsRequired);
    }

    private static boolean isClusterPerm(String action0) {
        return  (    action0.startsWith("cluster:")
                || action0.startsWith("indices:admin/template/")

            || action0.startsWith(SearchScrollAction.NAME)
            || (action0.equals(BulkAction.NAME))
            || (action0.equals(MultiGetAction.NAME))
            || (action0.equals(MultiSearchAction.NAME))
            || (action0.equals(MultiTermVectorsAction.NAME))
            || (action0.equals(ReindexAction.NAME))

            ) ;
    }

    private boolean checkFilteredAliases(Set<String> requestedResolvedIndices, String action) {
        //check filtered aliases
        for (String requestAliasOrIndex: requestedResolvedIndices) {

            final List<AliasMetadata> filteredAliases = new ArrayList<>();

            final IndexMetadata indexMetadata = clusterService.state().metadata().getIndices().get(requestAliasOrIndex);

            if (indexMetadata == null) {
                log.debug("{} does not exist in cluster metadata", requestAliasOrIndex);
                continue;
            }

            final ImmutableOpenMap<String, AliasMetadata> aliases = indexMetadata.getAliases();

            if(aliases != null && aliases.size() > 0) {

                if(log.isDebugEnabled()) {
                    log.debug("Aliases for {}: {}", requestAliasOrIndex, aliases);
                }

                final Iterator<String> it = aliases.keysIt();
                while(it.hasNext()) {
                    final String alias = it.next();
                    final AliasMetadata aliasMetadata = aliases.get(alias);

                    if (aliasMetadata != null && aliasMetadata.filteringRequired()) {
                        filteredAliases.add(aliasMetadata);
                        if(log.isDebugEnabled()) {
                            log.debug(alias+" is a filtered alias "+aliasMetadata.getFilter());
                        }
                    } else {
                        if(log.isDebugEnabled()) {
                            log.debug(alias+" is not an alias or does not have a filter");
                        }
                    }
                }
            }

            if(filteredAliases.size() > 1 && ACTION_MATCHER.test(action)) {
                //TODO add queries as dls queries (works only if dls module is installed)
                final String faMode = dcm.getFilteredAliasMode();// getConfigSettings().dynamic.filtered_alias_mode;
                if(faMode.equals("warn")) {
                    log.warn("More than one ({}) filtered alias found for same index ({}). This is currently not recommended. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                } else if (faMode.equals("disallow")) {
                    log.error("More than one ({}) filtered alias found for same index ({}). This is currently not supported. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("More than one ({}) filtered alias found for same index ({}). Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                    }
                }
            }
        } //end-for

        return false;
    }

    private List<String> toString(List<AliasMetadata> aliases) {
        if(aliases == null || aliases.size() == 0) {
            return Collections.emptyList();
        }

        final List<String> ret = new ArrayList<>(aliases.size());

        for(final AliasMetadata amd: aliases) {
            if(amd != null) {
                ret.add(amd.alias());
            }
        }

        return Collections.unmodifiableList(ret);
    }
}
