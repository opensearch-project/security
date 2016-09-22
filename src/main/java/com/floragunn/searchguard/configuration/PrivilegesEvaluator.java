/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.Sets;
import com.google.common.collect.UnmodifiableIterator;

public class PrivilegesEvaluator implements ConfigChangeListener {

    private static final Set<String> NULL_SET = Sets.newHashSet((String)null);
    private final Set<String> DLSFLS = ImmutableSet.of("_dls_", "_fls_");
    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final ClusterService clusterService;
    private volatile Settings rolesMapping;
    private volatile Settings roles;
    private final ActionGroupHolder ah;
    private final IndexNameExpressionResolver resolver;
    private final Map<Class<?>, Method> typeCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final Map<Class<?>, Method> typesCache = Collections.synchronizedMap(new HashMap<Class<?>, Method>(100));
    private final String[] deniedActionPatterns;
    private final AuditLog auditLog;

    private final String searchguardIndex;
    
    @Inject
    public PrivilegesEvaluator(final ClusterService clusterService, final TransportConfigUpdateAction tcua, final ActionGroupHolder ah,
            final IndexNameExpressionResolver resolver, AuditLog auditLog, final Settings settings) {
        super();
        tcua.addConfigChangeListener("rolesmapping", this);
        tcua.addConfigChangeListener("roles", this);
        this.clusterService = clusterService;
        this.ah = ah;
        this.resolver = resolver;
        this.auditLog = auditLog;
        this.searchguardIndex = settings.get(ConfigConstants.SG_CONFIG_INDEX, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        
        /*
        indices:admin/template/delete
        indices:admin/template/get
        indices:admin/template/put
        
        indices:admin/aliases
        indices:admin/aliases/exists
        indices:admin/aliases/get
        indices:admin/analyze
        indices:admin/cache/clear
        -> indices:admin/close
        indices:admin/create
        -> indices:admin/delete
        indices:admin/get
        indices:admin/exists
        indices:admin/flush
        indices:admin/mapping/put
        indices:admin/mappings/fields/get
        indices:admin/mappings/get
        indices:admin/open
        indices:admin/optimize
        indices:admin/refresh
        indices:admin/settings/update
        indices:admin/shards/search_shards
        indices:admin/types/exists
        indices:admin/upgrade
        indices:admin/validate/query
        indices:admin/warmers/delete
        indices:admin/warmers/get
        indices:admin/warmers/put
        */
        
        final List<String> deniedActionPatternsList = new ArrayList<String>();
        deniedActionPatternsList.add("indices:data/write*");
        deniedActionPatternsList.add("indices:admin/close");
        deniedActionPatternsList.add("indices:admin/delete");
        //deniedActionPatternsList.add("indices:admin/settings/update");
        //deniedActionPatternsList.add("indices:admin/upgrade");
        
        deniedActionPatterns = deniedActionPatternsList.toArray(new String[0]);
        
    }

    @Override
    public void onChange(final String event, final Settings settings) {
        switch (event) {
        case "roles":
            roles = settings;
            break;
        case "rolesmapping":
            rolesMapping = settings;
            break;
        }
    }

    @Override
    public boolean isInitialized() {
        return rolesMapping != null && roles != null;
    }

    @Override
    public void validate(final String event, final Settings settings) throws ElasticsearchSecurityException {

    }
    
    private static class IndexType {
        
        private String index;
        private String type;
        
        public IndexType(String index, String type) {
            super();
            this.index = index;
            this.type = type.equals("_all")? "*": type;
        }
 
        public String getCombinedString() {
            return index+type;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((index == null) ? 0 : index.hashCode());
            result = prime * result + ((type == null) ? 0 : type.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            IndexType other = (IndexType) obj;
            if (index == null) {
                if (other.index != null)
                    return false;
            } else if (!index.equals(other.index))
                return false;
            if (type == null) {
                if (other.type != null)
                    return false;
            } else if (!type.equals(other.type))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "IndexType [index=" + index + ", type=" + type + "]";
        }        
    }

    public boolean evaluate(final User user, final String action, final ActionRequest<?> request) {
        
        if(action.startsWith("cluster:admin/snapshot/restore")) {
            auditLog.logMissingPrivileges(action, request);
            log.warn(action + " is not allowed for a regular user");
            return false;
        }
        
        final TransportAddress caller = Objects.requireNonNull((TransportAddress) request.getFromContext(ConfigConstants.SG_REMOTE_ADDRESS));

        if (log.isDebugEnabled()) {
            log.debug("evaluate permissions for {}", user);
            log.debug("requested {} from {}", action, caller);
        }

        final ClusterState clusterState = clusterService.state();
        final MetaData metaData = clusterState.metaData();
        final Tuple<Set<String>, Set<String>> requestedResolvedAliasesIndicesTypes = resolve(user, action, request, metaData);

        final Set<String> requestedResolvedIndices = Collections.unmodifiableSet(requestedResolvedAliasesIndicesTypes.v1());        
        final Set<IndexType> requestedResolvedIndexTypes;
        
        {
            final Set<IndexType> requestedResolvedIndexTypes0 = new HashSet<IndexType>(requestedResolvedAliasesIndicesTypes.v1().size() * requestedResolvedAliasesIndicesTypes.v2().size());
            
            for(String index: requestedResolvedAliasesIndicesTypes.v1()) {
                for(String type: requestedResolvedAliasesIndicesTypes.v2()) {
                    requestedResolvedIndexTypes0.add(new IndexType(index, type));
                }
            }
            
            requestedResolvedIndexTypes = Collections.unmodifiableSet(requestedResolvedIndexTypes0);
        }
        

        if (log.isDebugEnabled()) {
            log.debug("requested resolved indextypes: {}", requestedResolvedIndexTypes);
        }
        
        if (requestedResolvedIndices.contains(searchguardIndex)
                && WildcardMatcher.matchAny(deniedActionPatterns, action)) {
            auditLog.logSgIndexAttempt(request, action);
            log.warn(action + " for '{}' index is not allowed for a regular user", searchguardIndex);
            return false;
        }

        if (requestedResolvedIndices.contains("_all")
                && WildcardMatcher.matchAny(deniedActionPatterns, action)) {
            auditLog.logSgIndexAttempt(request, action);
            log.warn(action + " for '_all' indices is not allowed for a regular user");
            return false;
        }
        
        if(requestedResolvedIndices.contains(searchguardIndex) || requestedResolvedIndices.contains("_all")) {
            
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

        final Set<String> sgRoles = mapSgRoles(user, caller);
       
        if (log.isDebugEnabled()) {
            log.debug("mapped roles: {}", sgRoles);
        }
        
        boolean allowAction = false;
        final Set<String> dlsQueries = new HashSet<String>();
        final Set<String> flsFields = new HashSet<String>();

        for (final Iterator<String> iterator = sgRoles.iterator(); iterator.hasNext();) {
            final String sgRole = (String) iterator.next();
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

           
            if (action.startsWith("cluster:") || action.startsWith("indices:admin/template/delete")
                    || action.startsWith("indices:admin/template/get") || action.startsWith("indices:admin/template/put") 
                || action.startsWith("indices:data/read/scroll")) {
                
                final Set<String> resolvedActions = resolveActions(sgRoleSettings.getAsArray(".cluster", new String[0]));

                if (log.isDebugEnabled()) {
                    log.debug("  resolved cluster actions:{}", resolvedActions);
                }

                if (WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                    if (log.isDebugEnabled()) {
                        log.debug("  found a match for '{}' and {}, skip other roles", sgRole, action);
                    }
                    return true;
                } else {
                    //check other roles #108
                    if (log.isDebugEnabled()) {
                        log.debug("  not match found a match for '{}' and {}, check next role", sgRole, action);
                    }
                    continue;
                }
            }

            final Map<String, Settings> permittedAliasesIndices = sgRoleSettings.getGroups(".indices");

            /*
            sg_role_starfleet:
            indices:
            sf: #<--- is an alias or cindex, can contain wildcards, will be resolved to concrete indices
            # if this contain wildcards we do a wildcard based check
            # if contains no wildcards we resolve this to concrete indices an do a exact check
            #

            ships:  <-- is a type, can contain wildcards
            - READ
            public:
            - 'indices:*'
            students:
            - READ
            alumni:
            - READ
            'admin*':
            - READ
            'pub*':
            '*':
            - READ
             */
            
            final ListMultimap<String, String> resolvedRoleIndices = Multimaps.synchronizedListMultimap(ArrayListMultimap
                    .<String, String> create());
            
            final Set<IndexType> _requestedResolvedIndexTypes = new HashSet<IndexType>(requestedResolvedIndexTypes);            
            //iterate over all beneath indices:
            permittedAliasesIndices:
            for (final String permittedAliasesIndex : permittedAliasesIndices.keySet()) {
                
                //final Map<String, Settings> permittedTypes = sgRoleSettings.getGroups(".indices."+permittedAliasesIndex);
                
                //System.out.println(permittedTypes);

                if (WildcardMatcher.containsWildcard(permittedAliasesIndex)) {
                    if (log.isDebugEnabled()) {
                        log.debug("  Try wildcard match for {}", permittedAliasesIndex);
                    }

                    handleIndicesWithWildcard(action, permittedAliasesIndex, permittedAliasesIndices, requestedResolvedIndexTypes, _requestedResolvedIndexTypes, requestedResolvedIndices);

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("  Resolve and match {}", permittedAliasesIndex);
                    }

                    handleIndicesWithoutWildcard(action, permittedAliasesIndex, permittedAliasesIndices, requestedResolvedIndexTypes, _requestedResolvedIndexTypes);
                }

                if (log.isDebugEnabled()) {
                    log.debug("For index {} remaining requested indextype: {}", permittedAliasesIndex, _requestedResolvedIndexTypes);
                }
                
                if (_requestedResolvedIndexTypes.isEmpty() && _requestedResolvedIndexTypes.isEmpty()) {
                    
                    int filteredAliasCount = 0;
                    
                    //check filtered aliases
                    for(String requestAliasOrIndex: requestedResolvedIndices) {      

                        //System.out.println(clusterState.metaData().getAliasAndIndexLookup().get(requestAliasOrIndex));
                        IndexMetaData indexMetaData = clusterState.metaData().getIndices().get(requestAliasOrIndex);
                        
                        if(indexMetaData == null) {
                            log.warn("{} does not exist in cluster metadata", requestAliasOrIndex);
                            continue;
                        }
                        
                        ImmutableOpenMap<String, AliasMetaData> aliases = indexMetaData.getAliases();
                        
                        log.debug("Aliases for {}: {}", requestAliasOrIndex, aliases);
                        
                        if(aliases != null && aliases.size() > 0) {
                        
                            UnmodifiableIterator<String> it = aliases.keysIt();
                            while(it.hasNext()) {
                                String a = it.next();
                                AliasMetaData aliasMetaData = aliases.get(a);
                                
                                if(aliasMetaData != null && aliasMetaData.filteringRequired()) {
                                    filteredAliasCount++;
                                    log.debug(a+" is a filtered alias "+aliasMetaData.getFilter());
                                } else {
                                    log.debug(a+" is not an alias or does not have a filter");
                                }
                                
                            }
                            
                        }
                    }
                    
                    if(filteredAliasCount > 1) {
                        //TODO add queries as dls queries (works only if dls module is installed)
                        log.warn("More than one ({}) filtered alias found for same index ({}). This is currently not supported", filteredAliasCount, permittedAliasesIndex);
                        continue permittedAliasesIndices;
                    }
                    
                    if (log.isDebugEnabled()) {
                        log.debug("found a match for '{}.{}', evaluate other roles", sgRole, permittedAliasesIndex);
                    }
                
                    resolvedRoleIndices.put(sgRole, permittedAliasesIndex);
                }
                
            }// end loop permittedAliasesIndices

            if (!resolvedRoleIndices.isEmpty()) {                
                for(String resolvedRole: resolvedRoleIndices.keySet()) {
                    for(String resolvedIndex: resolvedRoleIndices.get(resolvedRole)) {                        
                        
                        String dls = roles.get(resolvedRole+".indices."+resolvedIndex+"._dls_");
                        final String[] fls = roles.getAsArray(resolvedRole+".indices."+resolvedIndex+"._fls_");
                        
                        if(dls != null && dls.length() > 0) {
                            
                            //TODO use UserPropertyReplacer, make it registerable for ldap user
                            dls = dls.replace("${user.name}", user.getName());
                            
                            dlsQueries.add(dls);
                                                
                            if (log.isDebugEnabled()) {
                                log.debug("dls query {}", dls);
                            }
                            
                        }
                        
                        if(fls != null && fls.length > 0) {
                            
                            flsFields.addAll(Sets.newHashSet(fls));
                            
                            if (log.isDebugEnabled()) {
                                log.debug("fls fields {}", Sets.newHashSet(fls));
                            }
                            
                        }
                        
                    }
                }
                
                allowAction = true;
            }

        } // end sg role loop

        if (!allowAction && log.isInfoEnabled()) {
            log.info("No perm match for {} and {}", action, sgRoles);
        }
        
        if(!dlsQueries.isEmpty()) {
            request.putHeader(ConfigConstants.SG_DLS_QUERY, Base64Helper.serializeObject((Serializable)dlsQueries));
        }
        
        if(!flsFields.isEmpty()) {
            request.putHeader(ConfigConstants.SG_FLS_FIELDS, Base64Helper.serializeObject((Serializable)flsFields));
        }
        
        return allowAction;
    }

    
    //---- end evaluate()
    
    public Set<String> mapSgRoles(User user, TransportAddress caller) {
        
        if(user == null) {
            return Collections.emptySet();
        }
        
        final Set<String> sgRoles = new TreeSet<String>();
        for (final String roleMap : rolesMapping.names()) {
            final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);
            if (WildcardMatcher.matchAny(roleMapSettings.getAsArray(".backendroles"), user.getRoles().toArray(new String[0]))) {
                sgRoles.add(roleMap);
                continue;
            }

            if (WildcardMatcher.matchAny(roleMapSettings.getAsArray(".users"), user.getName())) {
                sgRoles.add(roleMap);
                continue;
            }

            if (caller != null &&  WildcardMatcher.matchAny(roleMapSettings.getAsArray(".hosts"), caller.getAddress())) {
                sgRoles.add(roleMap);
                continue;
            }

            if (caller != null && WildcardMatcher.matchAny(roleMapSettings.getAsArray(".hosts"), caller.getHost())) {
                sgRoles.add(roleMap);
                continue;
            }

        }
        
        return Collections.unmodifiableSet(sgRoles);

    }

    private void handleIndicesWithWildcard(final String action, final String permittedAliasesIndex,
            final Map<String, Settings> permittedAliasesIndices, final Set<IndexType> requestedResolvedIndexTypes, final Set<IndexType> _requestedResolvedIndexTypes, final Set<String> requestedResolvedIndices0) {
        
        List<String> wi = null;
        if (!(wi = WildcardMatcher.getMatchAny(permittedAliasesIndex, requestedResolvedIndices0.toArray(new String[0]))).isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("  Wildcard match for {}: {}", permittedAliasesIndex, wi);
            }

            final Set<String> permittedTypes = new HashSet<String>(permittedAliasesIndices.get(permittedAliasesIndex).names());
            permittedTypes.removeAll(DLSFLS);
            
            if (log.isDebugEnabled()) {
                log.debug("  matches for {}, will check now types {}", permittedAliasesIndex, permittedTypes);
            }

            for (final String type : permittedTypes) {
                
                final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsArray(type));

                if (WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                    if (log.isDebugEnabled()) {
                        log.debug("    match requested action {} against {}/{}: {}", action, permittedAliasesIndex, type, resolvedActions);
                    }

                    for(String it: wi) {
                        boolean removed = wildcardRemoveFromSet(_requestedResolvedIndexTypes, new IndexType(it, type));
                        
                        if(removed) {
                            log.debug("    removed {}", it+type);
                        } else {
                            log.debug("    no match {} in {}", it+type, _requestedResolvedIndexTypes);
                        }
                    }
                }
                
            }  
        } else {
            if (log.isDebugEnabled()) {
                log.debug("  No wildcard match found for {}", permittedAliasesIndex);
            }

            return;
        }
    }

    private void handleIndicesWithoutWildcard(final String action, final String permittedAliasesIndex,
            final Map<String, Settings> permittedAliasesIndices, final Set<IndexType> requestedResolvedIndexTypes, final Set<IndexType> _requestedResolvedIndexTypes) {

        final Set<String> resolvedPermittedAliasesIndex = new HashSet<String>();
        
        if(!resolver.hasIndexOrAlias(permittedAliasesIndex, clusterService.state())) {
            
            if(log.isDebugEnabled()) {
                log.debug("no permittedAliasesIndex '{}' found for  '{}'", permittedAliasesIndex,  action);
                
                
                for(String pai: permittedAliasesIndices.keySet()) {
                    Settings paiSettings = permittedAliasesIndices.get(pai);
                    log.debug("permittedAliasesIndices '{}' -> '{}'", permittedAliasesIndices, paiSettings==null?"null":String.valueOf(paiSettings.getAsMap()));
                }
                
                log.debug("requestedResolvedIndexTypes '{}'", requestedResolvedIndexTypes);   
            }
            
            resolvedPermittedAliasesIndex.add(permittedAliasesIndex);

        } else {
            resolvedPermittedAliasesIndex.addAll(Arrays.asList(resolver.concreteIndices(
                    clusterService.state(), IndicesOptions.fromOptions(false, true, true, false), permittedAliasesIndex)));
        }
        
        
        if (log.isDebugEnabled()) {
            log.debug("  resolved permitted aliases indices for {}: {}", permittedAliasesIndex, resolvedPermittedAliasesIndex);
        }

        //resolvedPermittedAliasesIndex -> resolved indices from role entry n
        final Set<String> permittedTypes = new HashSet<String>(permittedAliasesIndices.get(permittedAliasesIndex).names());
        permittedTypes.removeAll(DLSFLS);
        
        if (log.isDebugEnabled()) {
            log.debug("  matches for {}, will check now types {}", permittedAliasesIndex, permittedTypes);
        }

        for (final String type : permittedTypes) {
            
            final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsArray(type));

            if (WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                if (log.isDebugEnabled()) {
                    log.debug("    match requested action {} against {}/{}: {}", action, permittedAliasesIndex, type, resolvedActions);
                }

                for(String resolvedPermittedIndex: resolvedPermittedAliasesIndex) {
                    boolean removed = wildcardRemoveFromSet(_requestedResolvedIndexTypes, new IndexType(resolvedPermittedIndex, type));
                    
                    if(removed) {
                        log.debug("    removed {}", resolvedPermittedIndex+type);

                    } else {
                        log.debug("    no match {} in {}", resolvedPermittedIndex+type, _requestedResolvedIndexTypes);
                    }
                }
            }
        }
    }

    private Tuple<Set<String>, Set<String>> resolve(final User user, final String action, final TransportRequest request,
            final MetaData metaData) {

        if (!(request instanceof CompositeIndicesRequest) && !(request instanceof IndicesRequest)) {

            if (log.isDebugEnabled()) {
                log.debug("{} is not an IndicesRequest", request.getClass());
            }

            return new Tuple<Set<String>, Set<String>>(Sets.newHashSet("_all"), Sets.newHashSet("_all"));
        }

        final Set<String> indices = new HashSet<String>();
        final Set<String> types = new HashSet<String>();

        if (request instanceof CompositeIndicesRequest) {
            for (final IndicesRequest indicesRequest : ((CompositeIndicesRequest) request).subRequests()) {
                final Tuple<Set<String>, Set<String>> t = resolve(user, action, indicesRequest, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
            }
        } else {
            final Tuple<Set<String>, Set<String>> t = resolve(user, action, (IndicesRequest) request, metaData);
            indices.addAll(t.v1());
            types.addAll(t.v2());
        }
        
        //for PutIndexTemplateRequest the index does not exists yet typically
        if (IndexNameExpressionResolver.isAllIndices(new ArrayList<String>(indices))) {
            if(log.isDebugEnabled()) {
                log.debug("The following list are '_all' indices: {}", indices);
            }
            indices.clear();
            indices.add("_all");
        }

        if (types.isEmpty()) {
            types.add("_all");
        }

        return new Tuple<Set<String>, Set<String>>(Collections.unmodifiableSet(indices), Collections.unmodifiableSet(types));
    }

    private Tuple<Set<String>, Set<String>> resolve(final User user, final String action, final IndicesRequest request,
            final MetaData metaData) {

        if (log.isDebugEnabled()) {
            log.debug("Resolve {} from {}", request.indices(), request.getClass());
        }

        final Class<? extends IndicesRequest> requestClass = request.getClass();
        final Set<String> requestTypes = new HashSet<String>();
        
        Method typeMethod = null;
        if(typeCache.containsKey(requestClass)) {
            typeMethod = typeCache.get(requestClass);
        } else {
            try {
                typeMethod = requestClass.getMethod("type");
                typeCache.put(requestClass, typeMethod);
            } catch (NoSuchMethodException e) {
                typeCache.put(requestClass, null);
            } catch (SecurityException e) {
                log.error("Cannot evaluate type() for {} due to {}", requestClass, e);
            }
            
        }
        
        Method typesMethod = null;
        if(typesCache.containsKey(requestClass)) {
            typesMethod = typesCache.get(requestClass);
        } else {
            try {
                typesMethod = requestClass.getMethod("types");
                typesCache.put(requestClass, typesMethod);
            } catch (NoSuchMethodException e) {
                typesCache.put(requestClass, null);
            } catch (SecurityException e) {
                log.error("Cannot evaluate types() for {} due to {}", requestClass, e);
            }
            
        }
        
        if(typeMethod != null) {
            try {
                String type = (String) typeMethod.invoke(request);
                if(type != null) {
                    requestTypes.add(type);
                }
            } catch (Exception e) {
                log.error("Unable to invoke type() for {} due to {}", e, requestClass, e);
            }
        }
        
        if(typesMethod != null) {
            try {
                final String[] types = (String[]) typesMethod.invoke(request);
                
                if(types != null) {
                    requestTypes.addAll(Arrays.asList(types));
                }
            } catch (Exception e) {
                log.error("Unable to invoke types() for {} due to {}", e, requestClass, e);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("indicesOptions {}", request.indicesOptions());
            log.debug("raw indices {}", Arrays.toString(request.indices()));
        }

        final Set<String> indices = new HashSet<String>();

        if(request.indices() == null || request.indices().length == 0 || new HashSet<String>(Arrays.asList(request.indices())).equals(NULL_SET)) {
            
            if(log.isDebugEnabled()) {
                log.debug("No indices found in request, assume _all");
            }
            
            indices.addAll(Arrays.asList(resolver.concreteIndices(clusterService.state(), IndicesOptions.strictExpand(), "*")));
            
        } else {
            
            try {
                indices.addAll(Arrays.asList(resolver.concreteIndices(clusterService.state(), request)));
                if(log.isDebugEnabled()) {
                    log.debug("Resolved {} to {}", request.indices(), indices);
                }
            } catch (final Exception e) {
                log.debug("Cannot resolve {} (due to {}) so we use the raw values", Arrays.toString(request.indices()), e);
                indices.addAll(Arrays.asList(request.indices()));
            }
        }
        
        return new Tuple<Set<String>, Set<String>>(indices, requestTypes);
    }

    private Set<String> resolveActions(final String[] actions) {
        final Set<String> resolvedActions = new HashSet<String>();
        for (int i = 0; i < actions.length; i++) {
            final String string = actions[i];
            final Set<String> groups = ah.getGroupMembers(string);
            if (groups.isEmpty()) {
                resolvedActions.add(string);
            } else {
                resolvedActions.addAll(groups);
            }
        }

        return resolvedActions;
    }
    
    private boolean wildcardRemoveFromSet(Set<IndexType> set, IndexType stringContainingWc) {      
        if(set.contains(stringContainingWc)) {
            return set.remove(stringContainingWc);
        } else {
            boolean modified = false;
            Set<IndexType> copy = new HashSet<IndexType>(set);
            
            for(IndexType it: copy) {
                if(WildcardMatcher.match(stringContainingWc.getCombinedString(), it.getCombinedString())) {
                    modified = set.remove(it) | modified;
                }
            }
            return modified;
        }  
    }
}
