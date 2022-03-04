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
 * Portions Copyright OpenSearch Contributors
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
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableSet;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
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
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Strings;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.greenrobot.eventbus.Subscribe;

import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import com.google.common.collect.Sets;

import static org.opensearch.security.OpenSearchSecurityPlugin.traceAction;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT;

public class PrivilegesEvaluator {

    private static final WildcardMatcher ACTION_MATCHER = WildcardMatcher.from("indices:data/read/*search*");

    private static final Pattern DNFOF_PATTERNS = Pattern.compile(
            "indices:(data/read/.*|(admin/(mappings/fields/get.*|shards/search_shards|resolve/index)))"
    );

    private static final IndicesOptions ALLOW_EMPTY = IndicesOptions.fromOptions(true, true, false, false);

    protected final Logger log = LoggerFactory.getLogger(this.getClass());
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
    private final SecurityIndexAccessEvaluator securityIndexAccessEvaluator;
    private final ProtectedIndexAccessEvaluator protectedIndexAccessEvaluator;
    private final TermsAggregationEvaluator termsAggregationEvaluator;
    private final boolean dlsFlsEnabled;
    private DynamicConfigModel dcm;
    private final NamedXContentRegistry namedXContentRegistry;
    
    public PrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool,
                               final ConfigurationRepository configurationRepository, final IndexNameExpressionResolver resolver,
                               AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor, final ClusterInfoHolder clusterInfoHolder,
                               final IndexResolverReplacer irr, boolean dlsFlsEnabled, NamedXContentRegistry namedXContentRegistry) {

        super();
        this.clusterService = clusterService;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.privilegesInterceptor = privilegesInterceptor;


        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);

        this.clusterInfoHolder = clusterInfoHolder;
        this.irr = irr;
        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, auditLog);
        securityIndexAccessEvaluator = new SecurityIndexAccessEvaluator(settings, auditLog, irr);
        protectedIndexAccessEvaluator = new ProtectedIndexAccessEvaluator(settings, auditLog);
        termsAggregationEvaluator = new TermsAggregationEvaluator();
        this.namedXContentRegistry = namedXContentRegistry;
        this.dlsFlsEnabled = dlsFlsEnabled;
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
            joiner.add(String.join(",", Sets.union(user.getSecurityRoles(), mappedRoles)));
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
            throw new OpenSearchSecurityException("OpenSearch Security is not initialized.");
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

        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();

        final TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        Set<String> mappedRoles = (injectedRoles == null) ? mapRoles(user, caller) : injectedRoles;
        final String injectedRolesValidationString = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION);
        if(injectedRolesValidationString != null) {
            HashSet<String> injectedRolesValidationSet = new HashSet<>(Arrays.asList(injectedRolesValidationString.split(",")));
            if(!mappedRoles.containsAll(injectedRolesValidationSet)) {
                presponse.allowed = false;
                presponse.missingSecurityRoles.addAll(injectedRolesValidationSet);
                log.info("Roles {} are not mapped to the user {}", injectedRolesValidationSet, user);
                return presponse;
            }
            mappedRoles = ImmutableSet.copyOf(injectedRolesValidationSet);
        }
        presponse.resolvedSecurityRoles.addAll(mappedRoles);
        final SecurityRoles securityRoles = getSecurityRoles(mappedRoles);

        setUserInfoInThreadContext(user, mappedRoles);

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("Action: {} ({})", action0, request.getClass().getSimpleName());
            log.debug("Mapped roles: {}", mappedRoles.toString());
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
        presponse.resolved = requestedResolved;


        if (isDebugEnabled) {
            log.debug("RequestedResolved : {}", requestedResolved);
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

        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("dnfof enabled? {}", dnfofEnabled);
        }

        presponse.evaluatedDlsFlsConfig = getSecurityRoles(mappedRoles).getDlsFls(user, resolver, clusterService, namedXContentRegistry);
        

        if (isClusterPerm(action0)) {
            if(!securityRoles.impliesClusterPermissionPermission(action0)) {
                presponse.missingPrivileges.add(action0);
                presponse.allowed = false;
                log.info("No cluster-level perm match for {} {} [Action [{}]] [RolesChecked {}]. No permissions for {}",  user, requestedResolved, action0,
                        securityRoles.getRoleNames(), presponse.missingPrivileges);
                return presponse;
            } else {

                if(request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
                    if (isDebugEnabled) {
                        log.debug("Normally allowed but we need to apply some extra checks for a restore request.");
                    }
                } else {
                    if(privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

                        final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(request, action0, user, dcm, requestedResolved,
                                mapTenants(user, mappedRoles));

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
        if (termsAggregationEvaluator.evaluate(requestedResolved, request, clusterService, user, securityRoles, resolver, presponse) .isComplete()) {
            return presponse;
        }

        final Set<String> allIndexPermsRequired = evaluateAdditionalIndexPermissions(request, action0);
        final String[] allIndexPermsRequiredA = allIndexPermsRequired.toArray(new String[0]);

        if (isDebugEnabled) {
            log.debug("Requested {} from {}", allIndexPermsRequired, caller);
        }

        presponse.missingPrivileges.clear();
        presponse.missingPrivileges.addAll(allIndexPermsRequired);

        if (isDebugEnabled) {
            log.debug("Requested resolved index types: {}", requestedResolved);
            log.debug("Security roles: {}", securityRoles.getRoleNames());
        }

        //TODO exclude Security index

        if(privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {

            final PrivilegesInterceptor.ReplaceResult replaceResult = privilegesInterceptor.replaceDashboardsIndex(request, action0, user, dcm, requestedResolved, mapTenants(user, mappedRoles));

            if (isDebugEnabled) {
                log.debug("Result from privileges interceptor: {}", replaceResult);
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

        if (dnfofEnabled && DNFOF_PATTERNS.matcher(action0).matches()) {

            if(requestedResolved.getAllIndices().isEmpty()) {
                presponse.missingPrivileges.clear();
                presponse.allowed = true;
                return presponse;
            }

            Set<String> reduced = securityRoles.reduce(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

            if(reduced.isEmpty()) {
                if(dcm.isDnfofForEmptyResultsEnabled() && request instanceof IndicesRequest.Replaceable) {

                    ((IndicesRequest.Replaceable) request).indices(new String[0]);
                    presponse.missingPrivileges.clear();
                    presponse.allowed = true;

                    if(request instanceof SearchRequest) {
                        ((SearchRequest) request).indicesOptions(ALLOW_EMPTY);
                    } else if(request instanceof ClusterSearchShardsRequest) {
                        ((ClusterSearchShardsRequest) request).indicesOptions(ALLOW_EMPTY);
                    } else if(request instanceof GetFieldMappingsRequest) {
                        ((GetFieldMappingsRequest) request).indicesOptions(ALLOW_EMPTY);
                    }

                    return presponse;
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

        if (isDebugEnabled) {
            log.debug("Security roles: {}", securityRoles.getRoleNames());
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

            if(checkFilteredAliases(requestedResolved, action0, isDebugEnabled)) {
                presponse.allowed=false;
                return presponse;
            }

            if (isDebugEnabled) {
                log.debug("Allowed because we have all indices permissions for {}", action0);
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
                && dcm.isDashboardsMultitenancyEnabled();
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && dcm.isDnfofEnabled();
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
            additionalPermissionsRequired.addAll(ConfigConstants.SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES);
        }

        if (additionalPermissionsRequired.size() > 1) {
            traceAction("Additional permissions required: {}", additionalPermissionsRequired);
        }

        if (log.isDebugEnabled() && additionalPermissionsRequired.size() > 1) {
            log.debug("Additional permissions required: {}", additionalPermissionsRequired);
        }

        return Collections.unmodifiableSet(additionalPermissionsRequired);
    }

    public static boolean isClusterPerm(String action0) {
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
                    return clusterService.state().getMetadata().getIndices().valuesIt();
                }
            };
        } else {
            Set<IndexMetadata> indexMetaDataSet = new HashSet<>(requestedResolved.getAllIndices().size());

            for (String requestAliasOrIndex : requestedResolved.getAllIndices()) {
                IndexMetadata indexMetaData = clusterService.state().getMetadata().getIndices().get(requestAliasOrIndex);
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
        //check filtered aliases
        for (IndexMetadata indexMetaData : indexMetaDataCollection) {

            final List<AliasMetadata> filteredAliases = new ArrayList<AliasMetadata>();

            final ImmutableOpenMap<String, AliasMetadata> aliases = indexMetaData.getAliases();

            if(aliases != null && aliases.size() > 0) {
                if (isDebugEnabled) {
                    log.debug("Aliases for {}: {}", indexMetaData.getIndex().getName(), aliases);
                }

                final Iterator<String> it = aliases.keysIt();
                while(it.hasNext()) {
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

            if(filteredAliases.size() > 1 && ACTION_MATCHER.test(action)) {
                //TODO add queries as dls queries (works only if dls module is installed)
                log.error("More than one ({}) filtered alias found for same index ({}). This is currently not supported. Aliases: {}",
                        filteredAliases.size(), indexMetaData.getIndex().getName(), toString(filteredAliases));
                return true;
            }
        } //end-for

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
