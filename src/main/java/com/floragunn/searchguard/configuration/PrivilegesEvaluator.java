/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.configuration;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.OriginalIndices;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.elasticsearch.action.get.MultiGetAction;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.search.MultiSearchAction;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchScrollAction;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.termvectors.MultiTermVectorsAction;
import org.elasticsearch.action.termvectors.MultiTermVectorsRequest;
import org.elasticsearch.action.termvectors.TermVectorsRequest;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.reindex.ReindexAction;
import org.elasticsearch.index.reindex.ReindexRequest;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.repositories.Repository;
import org.elasticsearch.search.aggregations.AggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.elasticsearch.snapshots.SnapshotId;
import org.elasticsearch.snapshots.SnapshotInfo;
import org.elasticsearch.snapshots.SnapshotUtils;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.RemoteClusterAware;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.resolver.IndexResolverReplacer;
import com.floragunn.searchguard.resolver.IndexResolverReplacer.Resolved;
import com.floragunn.searchguard.sgconf.ConfigModel;
import com.floragunn.searchguard.sgconf.ConfigModel.IndexPattern;
import com.floragunn.searchguard.sgconf.ConfigModel.SgRoles;
import com.floragunn.searchguard.sgconf.ConfigModel.TypePerm;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.Sets;

public class PrivilegesEvaluator {

    private static final Set<String> NO_INDICES_SET = Sets.newHashSet("\\",";",",","/","|");
    private static final Set<String> NULL_SET = Sets.newHashSet((String)null);
    private final Set<String> DLSFLS = ImmutableSet.of("_dls_", "_fls_"); //TODO check that types does not contain them
    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("sg_action_trace");
    private final ClusterService clusterService;
    private final ActionGroupHolder ah;
    private final IndexNameExpressionResolver resolver;
    private final Map<Class<?>, Method> typeCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final Map<Class<?>, Method> typesCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final String[] sgDeniedActionPatterns;
    private final AuditLog auditLog;
    private ThreadContext threadContext;
    private final static IndicesOptions DEFAULT_INDICES_OPTIONS = IndicesOptions.lenientExpandOpen();
    private final ConfigurationRepository configurationRepository;

    private final String searchguardIndex;
    private PrivilegesInterceptor privilegesInterceptor;
    
    private final boolean enableSnapshotRestorePrivilege;
    private final boolean checkSnapshotRestoreWritePrivileges;
    private ConfigConstants.RolesMappingResolution rolesMappingResolution;
    
    private final ClusterInfoHolder clusterInfoHolder;
    //private final boolean typeSecurityDisabled = false;
    private final ConfigModel configModel;
    private final IndexResolverReplacer irr;

    public PrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool, final ConfigurationRepository configurationRepository, final ActionGroupHolder ah,
            final IndexNameExpressionResolver resolver, AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor,
            final ClusterInfoHolder clusterInfoHolder) {

        super();
        this.configurationRepository = configurationRepository;
        this.clusterService = clusterService;
        this.ah = ah;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        this.privilegesInterceptor = privilegesInterceptor;
        this.enableSnapshotRestorePrivilege = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                ConfigConstants.SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE);
        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);
        
        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(settings.get(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString()).toUpperCase());
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution",e);
            rolesMappingResolution =  ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }
        
        final List<String> sgIndexdeniedActionPatternsList = new ArrayList<String>();
        sgIndexdeniedActionPatternsList.add("indices:data/write*");
        sgIndexdeniedActionPatternsList.add("indices:admin/close");
        sgIndexdeniedActionPatternsList.add("indices:admin/delete");
        //deniedActionPatternsList.add("indices:admin/settings/update");
        //deniedActionPatternsList.add("indices:admin/upgrade");
        
        sgDeniedActionPatterns = sgIndexdeniedActionPatternsList.toArray(new String[0]);
        this.clusterInfoHolder = clusterInfoHolder;
        //this.typeSecurityDisabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_DISABLE_TYPE_SECURITY, false);
        configModel = new ConfigModel(ah, configurationRepository);
        irr = new IndexResolverReplacer(resolver, clusterService);
    }
    
    private Settings getRolesSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES);
    }

    private Settings getRolesMappingSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES_MAPPING);
    }
    
    private Settings getConfigSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_CONFIG);
    }
    
    private SgRoles getSgRoles(final User user, final TransportAddress caller) {
        Set<String> roles = mapSgRoles(user, caller);
        return configModel.load().filter(roles);
    }
    
    
    public boolean isInitialized() {
        return getRolesSettings() != null && getRolesMappingSettings() != null && getConfigSettings() != null;
    }

    public static class PrivEvalResponse {
        boolean allowed = false;
        Set<String> missingPrivileges = new HashSet<String>();
        Map<String,Set<String>> allowedFlsFields;
        Map<String,Set<String>> queries; 
        
        public boolean isAllowed() {
            return allowed;
        }
        public Set<String> getMissingPrivileges() {
            return new HashSet<String>(missingPrivileges);
        }
        
        public Map<String,Set<String>> getAllowedFlsFields() {
            return allowedFlsFields;
        }
        
        public Map<String,Set<String>> getQueries() {
            return queries;
        }
    }
    
    public PrivEvalResponse evaluate(final User user, String action0, final ActionRequest request, Task task) {
           
        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Search Guard is not initialized.");
        }
        
        final Set<String> allPermsRequired = evaluateAdditionalPermissions(request, action0);
        final String[] allPermsRequiredA = allPermsRequired.toArray(new String[0]);
        
        final PrivEvalResponse presponse = new PrivEvalResponse();
        presponse.getMissingPrivileges().addAll(allPermsRequired);

        try {
            if(request instanceof SearchRequest) {
                SearchRequest sr = (SearchRequest) request;                
                if( 
                        sr.source() != null
                        && sr.source().query() == null
                        && sr.source().aggregations() != null
                        && sr.source().aggregations().getAggregatorFactories() != null
                        && sr.source().aggregations().getAggregatorFactories().size() == 1 
                        && sr.source().size() == 0) {
                   AggregationBuilder ab = sr.source().aggregations().getAggregatorFactories().get(0);                   
                   if(     ab instanceof TermsAggregationBuilder 
                           && "terms".equals(ab.getType()) 
                           && "indices".equals(ab.getName())) {                       
                       if("_index".equals(((TermsAggregationBuilder) ab).field()) 
                               && ab.getPipelineAggregations().isEmpty() 
                               && ab.getSubAggregations().isEmpty()) {                  
                           presponse.allowed = true;
                           return presponse;
                       }
                   }
                }
            }
        } catch (Exception e) {
            log.warn("Unable to evaluate terms aggregation",e);
        }
        
        final Settings config = getConfigSettings();
        //final Settings roles = getRolesSettings();

        //boolean clusterLevelPermissionRequired = false;
        
        final TransportAddress caller = Objects.requireNonNull((TransportAddress) this.threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS));
        
        if (log.isDebugEnabled()) {
            log.debug("### evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            //log.debug("evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("requested {} from {}", allPermsRequired, caller);
        }
        
        if(action0.startsWith("cluster:admin/snapshot/restore")) {
            if (enableSnapshotRestorePrivilege) {
                return presponse; //evaluateSnapshotRestore(user, action0, request, caller, task);
            } else {
                log.warn(action0 + " is not allowed for a regular user");
                return presponse;
            }
        }

        if(action0.startsWith("internal:indices/admin/upgrade")) {
            action0 = "indices:admin/upgrade";
        }

        //final ClusterState clusterState = clusterService.state();
        //final MetaData metaData = clusterState.metaData();
        
        boolean dnfof = false;

        final Resolved requestedResolved = irr.resolve(request);
        final SgRoles sgr = getSgRoles(user, caller);
        final Set<IndexPattern> ip = sgr.get(requestedResolved, user, allPermsRequiredA, resolver, clusterService);
        
        if (log.isDebugEnabled()) {
            log.debug("requested resolved indextypes: {}", requestedResolved);
        }
        
        System.out.println(sgr);
        
        if (log.isDebugEnabled()) {
            log.debug("Set<IndexPattern> ip: {}", ip);
        }
        
        if (requestedResolved.getAllIndices().contains(searchguardIndex)
                && WildcardMatcher.matchAny(sgDeniedActionPatterns, action0)) {
            auditLog.logSgIndexAttempt(request, action0, task);
            log.warn(action0 + " for '{}' index is not allowed for a regular user", searchguardIndex);
            return presponse;
        }

        //TODO: newpeval: check if isAll() is all (contains("_all" or "*"))
        if (requestedResolved.isAll()
                && WildcardMatcher.matchAny(sgDeniedActionPatterns, action0)) {
            auditLog.logSgIndexAttempt(request, action0, task);
            log.warn(action0 + " for '_all' indices is not allowed for a regular user");
            return presponse;
        }
        
        
        //TODO exclude sg index
        //irr.exclude(request, searchguardIndex);
        
        if(dnfof) {
            //boolean success = irr.replace(request, ip.stream().map(i->i.getIndexPattern(user)).toArray(String[]::new));
            //if(success) {
            //    throw new RuntimeException("Unable to replace indices");
            //}
        }
        

        
        
        //TODO: newpeval: check if isAll() is all (contains("_all" or "*"))
        if(requestedResolved.getAllIndices().contains(searchguardIndex) || requestedResolved.isAll()) {
            
            if(request instanceof SearchRequest) {
                ((SearchRequest)request).requestCache(Boolean.FALSE);
                if(log.isDebugEnabled()) {
                    log.debug("Disable search request cache for this request");
                }
            }
            
            if(request instanceof RealtimeRequest) {
                ((RealtimeRequest) request).realtime(Boolean.FALSE);
                if(log.isDebugEnabled()) {
                    log.debug("Disable realtime for this request");
                }
            }
        }

        //final Set<String> sgRoles = mapSgRoles(user, caller);
       
        //if (log.isDebugEnabled()) {
        //    log.debug("mapped roles for {}: {}", user.getName(), sgRoles);
        //}
        
        if(privilegesInterceptor.getClass() != PrivilegesInterceptor.class) {
        
            final Boolean replaceResult = privilegesInterceptor.replaceKibanaIndex(request, action0, user, config, requestedResolved.getAllIndices(), mapTenants(user, caller));
    
            if(log.isDebugEnabled()) {
                log.debug("Result from privileges interceptor: {}", replaceResult);
            }
            
            if (replaceResult == Boolean.TRUE) {
                auditLog.logMissingPrivileges(action0, request, task);
                return presponse;
            }
            
            if (replaceResult == Boolean.FALSE) {
                presponse.allowed = true;
                return presponse;
            }
        }
        
        //boolean allowAction = false;
        
        final Map<String,Set<String>> dlsQueries = new HashMap<String, Set<String>>();
        final Map<String,Set<String>> flsFields = new HashMap<String, Set<String>>();
        
        
        
        
        
        
        
        if (    action0.startsWith("cluster:") 
                || action0.startsWith("indices:admin/template/")

            || action0.startsWith(SearchScrollAction.NAME)
            || (action0.equals(BulkAction.NAME))
            || (action0.equals(MultiGetAction.NAME))
            || (action0.equals(MultiSearchAction.NAME))
            || (action0.equals(MultiTermVectorsAction.NAME))
            || (action0.equals("indices:data/read/coordinate-msearch"))
            || (action0.equals(ReindexAction.NAME))

            ) {
        
                //check cluster perms
                if(sgr.impliesClusterPermissionPermission(action0)) {
                
                    //TODO modify aliases SG-813
                    //if(request instanceof MultiGetRequest) {
                    //    ((MultiGetRequest) request).getItems().clear();
                    //}
                    
                    
                    presponse.allowed = true;
                    return presponse;
                }
        
        }
        
        boolean permGiven = false;
        
        for(IndexPattern ipat: ip) {
            final String dls = ipat.getDlsQuery(user);
            final Set<String> fls = ipat.getFls();
            final String indexPattern = ipat.getUnresolvedIndexPattern(user);
            
            //Set<TypePerm> tperms = ipat.getTypePerms();
            
            //only when dls and fls != null
            String[] concreteIndices = new String[0];
            
            if((dls != null && dls.length() > 0) || (fls != null && fls.size() > 0)) {
                concreteIndices = resolver.concreteIndexNames(clusterService.state(), DEFAULT_INDICES_OPTIONS,indexPattern);
            }
            
            if(dls != null && dls.length() > 0) {

                if(dlsQueries.containsKey(indexPattern)) {
                    dlsQueries.get(indexPattern).add(dls);
                } else {
                    dlsQueries.put(indexPattern, new HashSet<String>());
                    dlsQueries.get(indexPattern).add(dls);
                }
                
                
                for (int i = 0; i < concreteIndices.length; i++) {
                    final String ci = concreteIndices[i];
                    if(dlsQueries.containsKey(ci)) {
                        dlsQueries.get(ci).add(dls);
                    } else {
                        dlsQueries.put(ci, new HashSet<String>());
                        dlsQueries.get(ci).add(dls);
                    }
                }
                
                                    
                if (log.isDebugEnabled()) {
                    log.debug("dls query {} for {}", dls, Arrays.toString(concreteIndices));
                }
                
            }
            
            if(fls != null && fls.size() > 0) {
                
                if(flsFields.containsKey(indexPattern)) {
                    flsFields.get(indexPattern).addAll(Sets.newHashSet(fls));
                } else {
                    flsFields.put(indexPattern, new HashSet<String>());
                    flsFields.get(indexPattern).addAll(Sets.newHashSet(fls));
                }
                
                for (int i = 0; i < concreteIndices.length; i++) {
                    final String ci = concreteIndices[i];
                    if(flsFields.containsKey(ci)) {
                        flsFields.get(ci).addAll(Sets.newHashSet(fls));
                    } else {
                        flsFields.put(ci, new HashSet<String>());
                        flsFields.get(ci).addAll(Sets.newHashSet(fls));
                    }
                }
                
                if (log.isDebugEnabled()) {
                    log.debug("fls fields {} for {}", Sets.newHashSet(fls), Arrays.toString(concreteIndices));
                }
                
            }

            permGiven = permGiven || ipat.impliesPermission(requestedResolved.getTypes().toArray(new String[0]), allPermsRequiredA);
            System.out.println("check ip: "+indexPattern+" -> "+permGiven+" for "+allPermsRequired);
            System.out.println("ipat: "+ipat);
        }
        
        
        if(!dlsQueries.isEmpty()) {
            
            if(this.threadContext.getHeader(ConfigConstants.SG_DLS_QUERY_HEADER) != null) {
                if(!dlsQueries.equals((Map<String,Set<String>>) Base64Helper.deserializeObject(this.threadContext.getHeader(ConfigConstants.SG_DLS_QUERY_HEADER)))) {
                    throw new ElasticsearchSecurityException(ConfigConstants.SG_DLS_QUERY_HEADER+" does not match (SG 900D)");
                }
            } else {
                this.threadContext.putHeader(ConfigConstants.SG_DLS_QUERY_HEADER, Base64Helper.serializeObject((Serializable) dlsQueries));
                if(log.isDebugEnabled()) {
                    log.debug("attach DLS info: {}", dlsQueries);
                }
            }
            
            presponse.queries = new HashMap<>(dlsQueries);
            
            //FIX FLS
            /*if (!requestedResolvedIndices.isEmpty()) {
                for (Iterator<Entry<String, Set<String>>> it = presponse.queries.entrySet().iterator(); it.hasNext();) {
                    Entry<String, Set<String>> entry = it.next();
                    if (!WildcardMatcher.matchAny(entry.getKey(), requestedResolvedIndices, false)) {
                        it.remove();
                    }
                }
            }*/

        }
        
        if(!flsFields.isEmpty()) {
            
            if(this.threadContext.getHeader(ConfigConstants.SG_FLS_FIELDS_HEADER) != null) {
                if(!flsFields.equals((Map<String,Set<String>>) Base64Helper.deserializeObject(this.threadContext.getHeader(ConfigConstants.SG_FLS_FIELDS_HEADER)))) {
                    throw new ElasticsearchSecurityException(ConfigConstants.SG_FLS_FIELDS_HEADER+" does not match (SG 901D)");
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug(ConfigConstants.SG_FLS_FIELDS_HEADER+" already set");
                    }
                }
            } else {
                this.threadContext.putHeader(ConfigConstants.SG_FLS_FIELDS_HEADER, Base64Helper.serializeObject((Serializable) flsFields));
                if(log.isDebugEnabled()) {
                    log.debug("attach FLS info: {}", flsFields);
                }
            }
            
            presponse.allowedFlsFields = new HashMap<>(flsFields);
            
            //FIX FLS
            /*
            if (!requestedResolvedIndices.isEmpty()) {
                for (Iterator<Entry<String, Set<String>>> it = presponse.allowedFlsFields.entrySet().iterator(); it.hasNext();) {
                    Entry<String, Set<String>> entry = it.next();
                    if (!WildcardMatcher.matchAny(entry.getKey(), requestedResolvedIndices, false)) {
                        it.remove();
                    }
                }
            }*/
        }
        
        /*if(!allowAction 
                && privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && leftovers.size() > 0) {
            boolean interceptorAllow = privilegesInterceptor.replaceAllowedIndices(request, action, user, config, leftovers);
            presponse.allowed=interceptorAllow;
            return presponse;
        }*/
        
        
        if(!permGiven) {
            presponse.getMissingPrivileges().add(e);
        }
        
        presponse.allowed=permGiven;
        return presponse;
        
        /*
        

        for (final Iterator<String> iterator = sgRoles.iterator(); iterator.hasNext();) {
            final String sgRole = (String) iterator.next();
            final Settings sgRoleSettings = roles.getByPrefix(sgRole);


            final Map<String, Settings> permittedAliasesIndices0 = sgRoleSettings.getGroups(".indices");
            final Map<String, Settings> permittedAliasesIndices = new HashMap<String, Settings>(permittedAliasesIndices0.size());
            
            for (String origKey : permittedAliasesIndices0.keySet()) {
                permittedAliasesIndices.put(replaceProperties(origKey, user), permittedAliasesIndices0.get(origKey));

            final ListMultimap<String, String> resolvedRoleIndices = Multimaps.synchronizedListMultimap(ArrayListMultimap
                    .<String, String> create());
            
            final Set<IndexType> _requestedResolvedIndexTypes = new HashSet<IndexType>(requestedResolvedIndexTypes);
            //iterate over all beneath indices:
            permittedAliasesIndices:
            for (final String permittedAliasesIndex : permittedAliasesIndices.keySet()) {

                final String resolvedRole = sgRole;
                final String indexPattern = permittedAliasesIndex;
                
                String dls = roles.get(resolvedRole+".indices."+indexPattern+"._dls_");
                final List<String> fls = roles.getAsList(resolvedRole+".indices."+indexPattern+"._fls_");

                //only when dls and fls != null
                String[] concreteIndices = new String[0];
                
                if((dls != null && dls.length() > 0) || (fls != null && fls.size() > 0)) {
                    concreteIndices = resolver.concreteIndexNames(clusterService.state(), DEFAULT_INDICES_OPTIONS,indexPattern);
                }
                
                if(dls != null && dls.length() > 0) {

                    dls = replaceProperties(dls, user);

                    if(dlsQueries.containsKey(indexPattern)) {
                        dlsQueries.get(indexPattern).add(dls);
                    } else {
                        dlsQueries.put(indexPattern, new HashSet<String>());
                        dlsQueries.get(indexPattern).add(dls);
                    }
                    
                    
                    for (int i = 0; i < concreteIndices.length; i++) {
                        final String ci = concreteIndices[i];
                        if(dlsQueries.containsKey(ci)) {
                            dlsQueries.get(ci).add(dls);
                        } else {
                            dlsQueries.put(ci, new HashSet<String>());
                            dlsQueries.get(ci).add(dls);
                        }
                    }
                    
                                        
                    if (log.isDebugEnabled()) {
                        log.debug("dls query {} for {}", dls, Arrays.toString(concreteIndices));
                    }
                    
                }
                
                if(fls != null && fls.size() > 0) {
                    
                    if(flsFields.containsKey(indexPattern)) {
                        flsFields.get(indexPattern).addAll(Sets.newHashSet(fls));
                    } else {
                        flsFields.put(indexPattern, new HashSet<String>());
                        flsFields.get(indexPattern).addAll(Sets.newHashSet(fls));
                    }
                    
                    for (int i = 0; i < concreteIndices.length; i++) {
                        final String ci = concreteIndices[i];
                        if(flsFields.containsKey(ci)) {
                            flsFields.get(ci).addAll(Sets.newHashSet(fls));
                        } else {
                            flsFields.put(ci, new HashSet<String>());
                            flsFields.get(ci).addAll(Sets.newHashSet(fls));
                        }
                    }
                    
                    if (log.isDebugEnabled()) {
                        log.debug("fls fields {} for {}", Sets.newHashSet(fls), Arrays.toString(concreteIndices));
                    }
                    
                }

                String[] action0 = null;
                        
                if(!additionalPermissionsRequired.isEmpty()) {
                    action0 = additionalPermissionsRequired.toArray(new String[0]);
                } else {
                    action0 = new String[] {action};
                }
                
                if (WildcardMatcher.containsWildcard(permittedAliasesIndex)) {
                    if (log.isDebugEnabled()) {
                        log.debug("  Try wildcard match for {}", permittedAliasesIndex);
                    }
                    
                    handleIndicesWithWildcard(action0, permittedAliasesIndex, permittedAliasesIndices, requestedResolvedIndexTypes, _requestedResolvedIndexTypes, requestedResolvedIndices);

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("  Resolve and match {}", permittedAliasesIndex);
                    }

                    handleIndicesWithoutWildcard(action0, permittedAliasesIndex, permittedAliasesIndices, requestedResolvedIndexTypes, _requestedResolvedIndexTypes);
                }

                if (log.isDebugEnabled()) {
                    log.debug("For index {} remaining requested indextype: {}", permittedAliasesIndex, _requestedResolvedIndexTypes);
                }
                
                if (_requestedResolvedIndexTypes.isEmpty()) {
                    
                    //check filtered aliases
                    for(String requestAliasOrIndex: requestedResolvedIndices) {      
                        
                        final List<AliasMetaData> filteredAliases = new ArrayList<AliasMetaData>();

                        final IndexMetaData indexMetaData = clusterState.metaData().getIndices().get(requestAliasOrIndex);
                        
                        if(indexMetaData == null) {
                            log.debug("{} does not exist in cluster metadata", requestAliasOrIndex);
                            continue;
                        }
                        
                        final ImmutableOpenMap<String, AliasMetaData> aliases = indexMetaData.getAliases();
                        
                        if(aliases != null && aliases.size() > 0) {
                            
                            if(log.isDebugEnabled()) {
                                log.debug("Aliases for {}: {}", requestAliasOrIndex, aliases);
                            }
                        
                            final Iterator<String> it = aliases.keysIt();
                            while(it.hasNext()) {
                                final String alias = it.next();
                                final AliasMetaData aliasMetaData = aliases.get(alias);
                                
                                if(aliasMetaData != null && aliasMetaData.filteringRequired()) {
                                    filteredAliases.add(aliasMetaData);
                                    if(log.isDebugEnabled()) {
                                        log.debug(alias+" is a filtered alias "+aliasMetaData.getFilter());
                                    }
                                } else {
                                    if(log.isDebugEnabled()) {
                                        log.debug(alias+" is not an alias or does not have a filter");
                                    }
                                }
                            }
                        }

                        if(filteredAliases.size() > 1 && WildcardMatcher.match("indices:data/read/*search*", action)) {
                            //TODO add queries as dls queries (works only if dls module is installed)
                            final String faMode = config.get("searchguard.dynamic.filtered_alias_mode","warn");
                            
                            if(faMode.equals("warn")) {
                                log.warn("More than one ({}) filtered alias found for same index ({}). This is currently not recommended. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                            } else if (faMode.equals("disallow")) {
                                log.error("More than one ({}) filtered alias found for same index ({}). This is currently not supported. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                                continue permittedAliasesIndices;
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("More than one ({}) filtered alias found for same index ({}). Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                                }
                            }
                        }
                    } //end-for
                    
                    if (log.isDebugEnabled()) {
                        log.debug("found a match for '{}.{}', evaluate other roles", sgRole, permittedAliasesIndex);
                    }
                
                    resolvedRoleIndices.put(sgRole, permittedAliasesIndex);
                }
                
            }// end loop permittedAliasesIndices

            
            if (!resolvedRoleIndices.isEmpty()) {
                allowAction = true;
            }
            
            if(log.isDebugEnabled()) {
                log.debug("Added to leftovers {}=>{}", sgRole, _requestedResolvedIndexTypes);
            }

            leftovers.put(sgRole, _requestedResolvedIndexTypes);
            
        } // end sg role loop

        if (!allowAction && log.isInfoEnabled()) {
            
            String[] action0;
            
            if(!additionalPermissionsRequired.isEmpty()) {
                action0 = additionalPermissionsRequired.toArray(new String[0]);
            } else {
                action0 = new String[] {action};
            }
            
            log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", clusterLevelPermissionRequired?"cluster":"index" , user, requestedResolvedIndexTypes, action0, sgRoles);
            log.info("No permissions for {}", leftovers);
        }

        if(!dlsQueries.isEmpty()) {
            
            if(this.threadContext.getHeader(ConfigConstants.SG_DLS_QUERY_HEADER) != null) {
                if(!dlsQueries.equals((Map<String,Set<String>>) Base64Helper.deserializeObject(this.threadContext.getHeader(ConfigConstants.SG_DLS_QUERY_HEADER)))) {
                    throw new ElasticsearchSecurityException(ConfigConstants.SG_DLS_QUERY_HEADER+" does not match (SG 900D)");
                }
            } else {
                this.threadContext.putHeader(ConfigConstants.SG_DLS_QUERY_HEADER, Base64Helper.serializeObject((Serializable) dlsQueries));
                if(log.isDebugEnabled()) {
                    log.debug("attach DLS info: {}", dlsQueries);
                }
            }
            
            presponse.queries = new HashMap<>(dlsQueries);
            
            if (!requestedResolvedIndices.isEmpty()) {
                for (Iterator<Entry<String, Set<String>>> it = presponse.queries.entrySet().iterator(); it.hasNext();) {
                    Entry<String, Set<String>> entry = it.next();
                    if (!WildcardMatcher.matchAny(entry.getKey(), requestedResolvedIndices, false)) {
                        it.remove();
                    }
                }
            }

        }
        
        if(!flsFields.isEmpty()) {
            
            if(this.threadContext.getHeader(ConfigConstants.SG_FLS_FIELDS_HEADER) != null) {
                if(!flsFields.equals((Map<String,Set<String>>) Base64Helper.deserializeObject(this.threadContext.getHeader(ConfigConstants.SG_FLS_FIELDS_HEADER)))) {
                    throw new ElasticsearchSecurityException(ConfigConstants.SG_FLS_FIELDS_HEADER+" does not match (SG 901D)");
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug(ConfigConstants.SG_FLS_FIELDS_HEADER+" already set");
                    }
                }
            } else {
                this.threadContext.putHeader(ConfigConstants.SG_FLS_FIELDS_HEADER, Base64Helper.serializeObject((Serializable) flsFields));
                if(log.isDebugEnabled()) {
                    log.debug("attach FLS info: {}", flsFields);
                }
            }
            
            presponse.allowedFlsFields = new HashMap<>(flsFields);
            if (!requestedResolvedIndices.isEmpty()) {
                for (Iterator<Entry<String, Set<String>>> it = presponse.allowedFlsFields.entrySet().iterator(); it.hasNext();) {
                    Entry<String, Set<String>> entry = it.next();
                    if (!WildcardMatcher.matchAny(entry.getKey(), requestedResolvedIndices, false)) {
                        it.remove();
                    }
                }
            }
        }
        
        if(!allowAction 
                && privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && leftovers.size() > 0) {
            boolean interceptorAllow = privilegesInterceptor.replaceAllowedIndices(request, action, user, config, leftovers);
            presponse.allowed=interceptorAllow;
            return presponse;
        }
        
        presponse.allowed=allowAction;
        return presponse;*/
    }

    
    //---- end evaluate()
    
    /*private PrivEvalResponse evaluateSnapshotRestore(final User user, String action, final ActionRequest request, final TransportAddress caller, final Task task) {
        
        final PrivEvalResponse presponse = new PrivEvalResponse();
        presponse.missingPrivileges.add(action);
        
        if (!(request instanceof RestoreSnapshotRequest)) {
            return presponse;
        }

        final RestoreSnapshotRequest restoreRequest = (RestoreSnapshotRequest) request;

        // Do not allow restore of global state
        if (restoreRequest.includeGlobalState()) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " with 'include_global_state' enabled is not allowed");
            return presponse;
        }

        // Start resolve for RestoreSnapshotRequest
        final RepositoriesService repositoriesService = Objects.requireNonNull(SearchGuardPlugin.GuiceHolder.getRepositoriesService(), "RepositoriesService not initialized");     
        //hack, because it seems not possible to access RepositoriesService from a non guice class
        final Repository repository = repositoriesService.repository(restoreRequest.repository());
        SnapshotInfo snapshotInfo = null;

        for (final SnapshotId snapshotId : repository.getRepositoryData().getSnapshotIds()) {
            if (snapshotId.getName().equals(restoreRequest.snapshot())) {

                if(log.isDebugEnabled()) {
                    log.debug("snapshot found: {} (UUID: {})", snapshotId.getName(), snapshotId.getUUID());    
                }

                snapshotInfo = repository.getSnapshotInfo(snapshotId);
                break;
            }
        }

        if (snapshotInfo == null) {
            log.warn(action + " for repository '" + restoreRequest.repository() + "', snapshot '" + restoreRequest.snapshot() + "' not found");
            return presponse;
        }

        final List<String> requestedResolvedIndices = SnapshotUtils.filterIndices(snapshotInfo.indices(), restoreRequest.indices(), restoreRequest.indicesOptions());

        if (log.isDebugEnabled()) {
            log.debug("resolved indices for restore to: {}", requestedResolvedIndices.toString());
        }
        // End resolve for RestoreSnapshotRequest

        // Check if the source indices contain the searchguard index
        if (requestedResolvedIndices.contains(searchguardIndex) || requestedResolvedIndices.contains("_all")) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' as source index is not allowed", searchguardIndex);
            return presponse;
        }

        // Check if the renamed destination indices contain the searchguard index
        final List<String> renamedTargetIndices = renamedIndices(restoreRequest, requestedResolvedIndices);
        if (renamedTargetIndices.contains(searchguardIndex) || requestedResolvedIndices.contains("_all")) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' as target index is not allowed", searchguardIndex);
            return presponse;
        }

        // Check if the user has the required role to perform the snapshot restore operation
        final Set<String> sgRoles = mapSgRoles(user, caller);

        if (log.isDebugEnabled()) {
            log.debug("mapped roles: {}", sgRoles);
        }

        boolean allowedActionSnapshotRestore = false;

        final Set<String> renamedTargetIndicesSet = new HashSet<String>(renamedTargetIndices);
        final Set<IndexType> _renamedTargetIndices = new HashSet<IndexType>(renamedTargetIndices.size());
        for(final String index: renamedTargetIndices) {
            for(final String neededAction: ConfigConstants.SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES) {
                _renamedTargetIndices.add(new IndexTypeAction(index, "*", neededAction));
            }
        }
        
        final Settings roles = getRolesSettings();

        for (final Iterator<String> iterator = sgRoles.iterator(); iterator.hasNext();) {
            final String sgRole = iterator.next();
            final Settings sgRoleSettings = roles.getByPrefix(sgRole);

            if (sgRoleSettings.names().isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("sg_role {} is empty", sgRole);
                }

                continue;
            }

            if (log.isDebugEnabled()) {
                log.debug("---------- evaluate sg_role: {}", sgRole);
            }

            final Set<String> resolvedActions = resolveActions(sgRoleSettings.getAsList(".cluster", Collections.emptyList()));
            if (log.isDebugEnabled()) {
                log.debug("  resolved cluster actions:{}", resolvedActions);
            }

            if (WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                if (log.isDebugEnabled()) {
                    log.debug("  found a match for '{}' and {}, skip other roles", sgRole, action);
                }
                allowedActionSnapshotRestore = true;
            } else {
                // check other roles #108
                if (log.isDebugEnabled()) {
                    log.debug("  not match found a match for '{}' and {}, check next role", sgRole, action);
                }
            }

            if (checkSnapshotRestoreWritePrivileges) {
                final Map<String, Settings> permittedAliasesIndices0 = sgRoleSettings.getGroups(".indices", true);
                final Map<String, Settings> permittedAliasesIndices = new HashMap<String, Settings>(permittedAliasesIndices0.size());

                for (final String origKey : permittedAliasesIndices0.keySet()) {
                    permittedAliasesIndices.put(replaceProperties(origKey, user), permittedAliasesIndices0.get(origKey));
                }

                for (final String permittedAliasesIndex : permittedAliasesIndices.keySet()) {
                    if (log.isDebugEnabled()) {
                        log.debug("  Try wildcard match for {}", permittedAliasesIndex);
                    }

                    handleSnapshotRestoreWritePrivileges(ConfigConstants.SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES, permittedAliasesIndex, permittedAliasesIndices, renamedTargetIndicesSet, _renamedTargetIndices);

                    if (log.isDebugEnabled()) {
                        log.debug("For index {} remaining requested indextypeaction: {}", permittedAliasesIndex, _renamedTargetIndices);
                    }

                }// end loop permittedAliasesIndices
            }
        }

        if (checkSnapshotRestoreWritePrivileges && !_renamedTargetIndices.isEmpty()) {
            allowedActionSnapshotRestore = false;
        }

        if (!allowedActionSnapshotRestore) {
            auditLog.logMissingPrivileges(action, request, task);
            log.info("No perm match for {} [Action [{}]] [RolesChecked {}]", user, action, sgRoles);
        }
        
        presponse.allowed = allowedActionSnapshotRestore;
        return presponse;
    }

    private List<String> renamedIndices(final RestoreSnapshotRequest request, final List<String> filteredIndices) {
        final List<String> renamedIndices = new ArrayList<>();
        for (final String index : filteredIndices) {
            String renamedIndex = index;
            if (request.renameReplacement() != null && request.renamePattern() != null) {
                renamedIndex = index.replaceAll(request.renamePattern(), request.renameReplacement());
            }
            renamedIndices.add(renamedIndex);
        }
        return renamedIndices;
    }*/

    public Set<String> mapSgRoles(final User user, final TransportAddress caller) {
        
        final Settings rolesMapping = getRolesMappingSettings();
        final Set<String> sgRoles = new TreeSet<String>();
        
        if(user == null) {
            return Collections.emptySet();
        }
        
        if(rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
            if(log.isDebugEnabled()) {
                log.debug("Pass backendroles from {}", user);
            }
            sgRoles.addAll(user.getRoles());
        }
        
        if(rolesMapping != null && ((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH 
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {
            for (final String roleMap : rolesMapping.names()) {
                final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);
                
                if (WildcardMatcher.allPatternsMatched(roleMapSettings.getAsList(".and_backendroles", Collections.emptyList()).toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap);
                    continue;
                }
                
                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".backendroles", Collections.emptyList()).toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".users"), user.getName())) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (caller != null &&  WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), caller.getAddress())) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (caller != null && WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), caller.getAddress())) {
                    sgRoles.add(roleMap);
                    continue;
                }

            }
        }

        return Collections.unmodifiableSet(sgRoles);

    }
    
    public Map<String, Boolean> mapTenants(final User user, final TransportAddress caller) {
        
        if(user == null) {
            return Collections.emptyMap();
        }
        
        final Map<String, Boolean> result = new HashMap<String, Boolean>();
        result.put(user.getName(), true);
        
        for(String sgRole: mapSgRoles(user, caller)) {
            Settings tenants = getRolesSettings().getByPrefix(sgRole+".tenants.");
            
            if(tenants != null) {
                for(String tenant: tenants.names()) {
                    
                    if(tenant.equals(user.getName())) {
                        continue;
                    }
                    
                    if("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                        result.put(tenant, true);
                    } else {
                        if(!result.containsKey(tenant)) { //RW outperforms RO
                            result.put(tenant, false);
                        }
                    }
                }
            }
            
        }

        return Collections.unmodifiableMap(result);
    }


   /* private void handleSnapshotRestoreWritePrivileges(final Set<String> actions, final String permittedAliasesIndex,
                                              final Map<String, Settings> permittedAliasesIndices, final Set<String> requestedResolvedIndices, final Set<IndexType> requestedResolvedIndices0) {
        List<String> wi = null;
        if (!(wi = WildcardMatcher.getMatchAny(permittedAliasesIndex, requestedResolvedIndices.toArray(new String[0]))).isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("  Wildcard match for {}: {}", permittedAliasesIndex, wi);
            }

            // Get actions only for the catch all wildcard type '*'
            final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsList("*"));

            if (log.isDebugEnabled()) {
                log.debug("  matches for {}, will check now wildcard type '*'", permittedAliasesIndex);
            }

            //TODO check wa var
            List<String> wa = null;
            for (String at : resolvedActions) {
                if (!(wa = WildcardMatcher.getMatchAny(at, actions.toArray(new String[0]))).isEmpty()) {
                    if (log.isDebugEnabled()) {
                        log.debug("    match requested actions {} against {}/*: {}", actions, permittedAliasesIndex, resolvedActions);
                    }

                    for (String it : wi) {
                        boolean removed = wildcardRemoveFromSet(requestedResolvedIndices0, new IndexTypeAction(it, "*", at));

                        if (removed) {
                            log.debug("    removed {}", it + '*');
                        } else {
                            log.debug("    no match {} in {}", it + '*', requestedResolvedIndices0);
                        }

                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("  No wildcard match found for {}", permittedAliasesIndex);
            }
        }
    }*/

    
    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class 
                && getConfigSettings().getAsBoolean("searchguard.dynamic.kibana.multitenancy_enabled", true);
    }
    
    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("searchguard.dynamic.kibana.do_not_fail_on_forbidden", false);
    }
    
    public String kibanaIndex() {
        return getConfigSettings().get("searchguard.dynamic.kibana.index",".kibana");
    }
    
    public String kibanaServerUsername() {
        return getConfigSettings().get("searchguard.dynamic.kibana.server_username","kibanaserver");
    }
    
    /*public boolean kibanaIndexReadonly(final User user, final TransportAddress caller) {
        final Set<String> sgRoles = mapSgRoles(user, caller);
        
        final String kibanaIndex = kibanaIndex();
        
        for (final Iterator<String> iterator = sgRoles.iterator(); iterator.hasNext();) {
            final String sgRole = iterator.next();
            final Settings sgRoleSettings = getRolesSettings().getByPrefix(sgRole);
            
            if (sgRoleSettings.names().isEmpty()) {
                continue;
            }

            final Map<String, Settings> permittedAliasesIndices0 = sgRoleSettings.getGroups(".indices", true);
            final Map<String, Settings> permittedAliasesIndices = new HashMap<String, Settings>(permittedAliasesIndices0.size());

            for (String origKey : permittedAliasesIndices0.keySet()) {
               permittedAliasesIndices.put(replaceProperties(origKey, user), permittedAliasesIndices0.get(origKey));
            }
            
            for(String indexPattern: permittedAliasesIndices.keySet()) {                
                if(WildcardMatcher.match(indexPattern, kibanaIndex)) {
                    final Settings innerSettings = permittedAliasesIndices.get(indexPattern);
                    final List<String> perms = innerSettings.getAsList("*");
                    if(perms!= null && perms.size() > 0) {
                        if(WildcardMatcher.matchAny(ah.resolvedActions(perms).toArray(new String[0]), "indices:data/write/update")) {
                            return false;
                        }
                    }
                }
            }
        }

        return true;
    }*/
    
    private Set<String> evaluateAdditionalPermissions(final ActionRequest request, final String originalAction) {
      //--- check inner bulk requests
        final Set<String> additionalPermissionsRequired = new HashSet<>();
        additionalPermissionsRequired.add(originalAction);
        
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
        
        if(actionTrace.isTraceEnabled() && additionalPermissionsRequired.size() > 1) {
            actionTrace.trace(("Additional permissions required: "+additionalPermissionsRequired));
        }
        
        if(log.isDebugEnabled() && additionalPermissionsRequired.size() > 1) {
            log.debug("Additional permissions required: "+additionalPermissionsRequired);
        }
        
        return Collections.unmodifiableSet(additionalPermissionsRequired);
    }
}
