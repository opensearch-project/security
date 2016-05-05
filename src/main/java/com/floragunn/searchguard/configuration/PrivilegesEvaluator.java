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
import java.lang.reflect.InvocationTargetException;
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
import java.util.concurrent.ConcurrentHashMap;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.Sets;
import com.google.common.collect.Sets.SetView;

public class PrivilegesEvaluator implements ConfigChangeListener {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final ClusterService clusterService;
    private volatile Settings rolesMapping;
    private volatile Settings roles;
    private final ActionGroupHolder ah;
    private final IndexNameExpressionResolver resolver;
    private final Map<Class, Method> typeCache = Collections.synchronizedMap(new HashMap(100));
    private final Map<Class, Method> typesCache = Collections.synchronizedMap(new HashMap(100));

    @Inject
    public PrivilegesEvaluator(final ClusterService clusterService, final TransportConfigUpdateAction tcua, final ActionGroupHolder ah,
            final IndexNameExpressionResolver resolver) {
        super();
        tcua.addConfigChangeListener("rolesmapping", this);
        tcua.addConfigChangeListener("roles", this);
        this.clusterService = clusterService;
        this.ah = ah;
        this.resolver = resolver;
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
        // TODO Auto-generated method stub

    }

    public boolean evaluate(final User user, final String action, final ActionRequest request) {
        final TransportAddress caller = Objects.requireNonNull((TransportAddress) request.getFromContext(ConfigConstants.SG_REMOTE_ADDRESS));

        if (log.isDebugEnabled()) {
            log.debug("evaluate permissions for {}", user);
            log.debug("requested {} from {}", action, caller);
        }

        final ClusterState clusterState = clusterService.state();
        final MetaData metaData = clusterState.metaData();
        final Tuple<Set<String>, Set<String>> requestedResolvedAliasesIndicesTypes = resolve(user, action, request, metaData);

        final Set<String> requestedResolvedAliasesIndices = requestedResolvedAliasesIndicesTypes.v1();
        final Set<String> requestedResolvedTypes = requestedResolvedAliasesIndicesTypes.v2();

        if (log.isDebugEnabled()) {
            log.debug("requested resolved aliases and indices: {}", requestedResolvedAliasesIndices);
            log.debug("requested resolved types: {}", requestedResolvedTypes);
        }
        
        List<String> allowedAdminActions = new ArrayList<String>();
        allowedAdminActions.add("indices:admin/aliases/exists");
        allowedAdminActions.add("indices:admin/aliases/get");
        allowedAdminActions.add("indices:admin/analyze");
        allowedAdminActions.add("indices:admin/get");
        allowedAdminActions.add("indices:admin/exists");
        allowedAdminActions.add("indices:admin/mappings/fields/get");
        allowedAdminActions.add("indices:admin/mappings/get");
        allowedAdminActions.add("indices:admin/types/exists");
        allowedAdminActions.add("indices:admin/validate/query");
        allowedAdminActions.add("indices:admin/template/put");
        allowedAdminActions.add("indices:admin/template/get");
        
        if (requestedResolvedAliasesIndices.contains("searchguard")
                && (action.startsWith("indices:data/write") || (action.startsWith("indices:admin") && !allowedAdminActions.contains(action)))) {
            log.warn(action + " for 'searchguard' index is not allowed for a regular user");
            return false;
        }

        if (requestedResolvedAliasesIndices.contains("_all")
                && (action.startsWith("indices:data/write") || (action.startsWith("indices:admin") && !allowedAdminActions.contains(action)))) {
            log.warn(action + " for '_all' indices is not allowed for a regular user");
            return false;
        }
        
        if(requestedResolvedAliasesIndices.contains("searchguard") || requestedResolvedAliasesIndices.contains("_all")) {
            
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

        for (final Iterator iterator = sgRoles.iterator(); iterator.hasNext();) {
            final String sgRole = (String) iterator.next();
            final Settings sgRoleSettings = roles.getByPrefix(sgRole);

            if (sgRoleSettings.names().isEmpty()) {
                continue;
            }

            if (log.isDebugEnabled()) {
                log.debug("---------- evaluate sg_role: {}", sgRole);
            }

            final Set<String> _requestedResolvedAliasesIndices = new HashSet<String>(requestedResolvedAliasesIndices);
            final Set<String> _requestedResolvedTypes = new HashSet<String>(requestedResolvedTypes);

            if (action.startsWith("cluster:") || action.startsWith("indices:admin/template/delete")
                    || action.startsWith("indices:admin/template/get") || action.startsWith("indices:admin/template/put")) {

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
            
            

            for (final String permittedAliasesIndex : permittedAliasesIndices.keySet()) {

                if (WildcardMatcher.containsWildcard(permittedAliasesIndex)) {
                    if (log.isDebugEnabled()) {
                        log.debug("  Try wildcard match for {}", permittedAliasesIndex);
                    }

                    handleIndicesWithWildcard(action, permittedAliasesIndex, permittedAliasesIndices, requestedResolvedAliasesIndices,
                            requestedResolvedTypes, _requestedResolvedAliasesIndices, _requestedResolvedTypes);

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("  Resolve and match {}", permittedAliasesIndex);
                    }

                    handleIndicesWithoutWildcard(action, permittedAliasesIndex, permittedAliasesIndices, requestedResolvedAliasesIndices,
                            requestedResolvedTypes, _requestedResolvedAliasesIndices, _requestedResolvedTypes);
                }

            }// end loop permittedAliasesIndices

            if (log.isDebugEnabled()) {
                log.debug("remaining requested aliases and indices: {}", _requestedResolvedAliasesIndices);
                log.debug("remaining requested resolved types: {}", _requestedResolvedTypes);
            }

            if (_requestedResolvedAliasesIndices.isEmpty() && _requestedResolvedTypes.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("found a match for '{}', evaluate other roles for fls/dls purposes", sgRole);
                }

                String dls = sgRoleSettings.get(".dls");
                final String[] fls = sgRoleSettings.getAsArray(".fls");
                
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

    public Set<String> mapSgRoles(User user, TransportAddress caller) {
        
        if(user == null) {
            return Collections.EMPTY_SET;
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
            final Map<String, Settings> permittedAliasesIndices, final Set<String> requestedResolvedAliasesIndices,
            final Set<String> requestedResolvedTypes, final Set<String> _requestedResolvedAliasesIndices,
            final Set<String> _requestedResolvedTypes) {

        List<String> wi = null;

        // TODO is this secure?
        if (!(wi = WildcardMatcher.getMatchAny(permittedAliasesIndex, requestedResolvedAliasesIndices.toArray(new String[0]))).isEmpty()) {

            if (log.isDebugEnabled()) {
                log.debug("  Wildcard match for {}: {}", permittedAliasesIndex, wi);
            }

            final Set<String> permittedTypes = permittedAliasesIndices.get(permittedAliasesIndex).names();

            if (log.isDebugEnabled()) {
                log.debug("  matches for {}, will check now types {}", permittedAliasesIndex, permittedTypes);
            }

            for (final String type : permittedTypes) {
                List<String> typeMatches = null;
                if (!(typeMatches = WildcardMatcher.getMatchAny(type, requestedResolvedTypes.toArray(new String[0]))).isEmpty()) {
                    final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsArray(type));

                    if (log.isDebugEnabled()) {
                        log.debug("    resolvedActions for {}/{}: {}", permittedAliasesIndex, type, resolvedActions);
                    }

                    if (WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                        if (log.isDebugEnabled()) {
                            log.debug("    match requested action {} against {}/{}: {}", action, permittedAliasesIndex, type,
                                    resolvedActions);
                        }

                        _requestedResolvedAliasesIndices.removeAll(wi);
                        _requestedResolvedTypes.removeAll(typeMatches);

                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("    no match for {} against {}", type, requestedResolvedTypes);
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
            final Map<String, Settings> permittedAliasesIndices, final Set<String> requestedResolvedAliasesIndices,
            final Set<String> requestedResolvedTypes, final Set<String> _requestedResolvedAliasesIndices,
            final Set<String> _requestedResolvedTypes) {

        if(!resolver.hasIndexOrAlias(permittedAliasesIndex, clusterService.state())) {
            
            log.debug("permittedAliasesIndex {} {}", permittedAliasesIndex,  action);
            log.debug("permittedAliasesIndices {}", permittedAliasesIndices);
            log.debug("requestedResolvedAliasesIndices {}", requestedResolvedAliasesIndices);
            log.debug("_requestedResolvedAliasesIndices {}", _requestedResolvedAliasesIndices);            
            return;//TODO check create index
        }
        
        final Set<String> resolvedPermittedAliasesIndex = new HashSet<String>(Arrays.asList(resolver.concreteIndices(
                clusterService.state(), IndicesOptions.fromOptions(false, true, true, false), permittedAliasesIndex)));

        if (log.isDebugEnabled()) {
            log.debug("  resolved permitted aliases indices for {}: {}", permittedAliasesIndex, resolvedPermittedAliasesIndex);
        }

        final SetView<String> inters = Sets.intersection(requestedResolvedAliasesIndices, resolvedPermittedAliasesIndex);
        final Set<String> permittedTypes = permittedAliasesIndices.get(permittedAliasesIndex).names();

        if (log.isDebugEnabled()) {
            log.debug("  matches for {}, will check now types {}", permittedAliasesIndex, permittedTypes);
        }

        for (final String type : permittedTypes) {
            List<String> typeMatches = null;
            if (!(typeMatches = WildcardMatcher.getMatchAny(type, requestedResolvedTypes.toArray(new String[0]))).isEmpty()) {
                final Set<String> resolvedActions = resolveActions(permittedAliasesIndices.get(permittedAliasesIndex).getAsArray(type));

                if (log.isDebugEnabled()) {
                    log.debug("    resolvedActions for {}/{}: {}", permittedAliasesIndex, type, resolvedActions);
                }

                if (WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                    if (log.isDebugEnabled()) {
                        log.debug("    match requested action {} against {}/{}: {}", action, permittedAliasesIndex, type, resolvedActions);
                    }

                    _requestedResolvedAliasesIndices.removeAll(inters);
                    _requestedResolvedTypes.removeAll(typeMatches);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("    no match for {} against {}", type, requestedResolvedTypes);
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

            return new Tuple<Set<String>, Set<String>>(Collections.EMPTY_SET, Collections.EMPTY_SET);
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
            log.debug("The following list are '_all' indices: {}", indices);
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

        try {
            indices.addAll(Arrays.asList(resolver.concreteIndices(clusterService.state(), request)));
            log.debug("Resolved {} to {}", indices);
        } catch (final Exception e) {
            log.warn("Cannot resolve {} so we use the raw values", Arrays.toString(request.indices()));
            indices.addAll(Arrays.asList(request.indices()));
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
}
