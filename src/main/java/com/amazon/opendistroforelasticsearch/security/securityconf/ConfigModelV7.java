/*
 * Copyright 2015-2018 floragunn GmbH
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

package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModelV6.SecurityRole;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleMappingsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7.Index;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.TenantV7;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.base.Joiner;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Iterables;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.MultimapBuilder.SetMultimapBuilder;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;

public class ConfigModelV7 extends ConfigModel {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private ConfigConstants.RolesMappingResolution rolesMappingResolution;
    private ActionGroupResolver agr = null;
    private SecurityRoles securityRoles = null;
    private TenantHolder tenantHolder;
    private RoleMappingHolder roleMappingHolder;
    private SecurityDynamicConfiguration<RoleV7> roles;
    private SecurityDynamicConfiguration<TenantV7> tenants;

    public ConfigModelV7(
            SecurityDynamicConfiguration<RoleV7> roles,
            SecurityDynamicConfiguration<RoleMappingsV7> rolemappings,
            SecurityDynamicConfiguration<ActionGroupsV7> actiongroups,
            SecurityDynamicConfiguration<TenantV7> tenants,
            DynamicConfigModel dcm,
            Settings esSettings) {

        this.roles = roles;
        this.tenants = tenants;
        
        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(
                    esSettings.get(ConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString())
                            .toUpperCase());
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution", e);
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }
        
        agr = reloadActionGroups(actiongroups);
        securityRoles = reload(roles);
        tenantHolder = new TenantHolder(roles, tenants);
        roleMappingHolder = new RoleMappingHolder(rolemappings, dcm.getHostsResolverMode());
    }
    
    public Set<String> getAllConfiguredTenantNames() {
        return Collections.unmodifiableSet(tenants.getCEntries().keySet());
    }
    
    public SecurityRoles getSecurityRoles() {
        return securityRoles;
    }
    
    private static interface ActionGroupResolver {
        Set<String> resolvedActions(final List<String> actions);
    }
    
    private ActionGroupResolver reloadActionGroups(SecurityDynamicConfiguration<ActionGroupsV7> actionGroups) {
        return new ActionGroupResolver() {
            
            private Set<String> getGroupMembers(final String groupname) {

                if (actionGroups == null) {
                    return Collections.emptySet();
                }

                return Collections.unmodifiableSet(resolve(actionGroups, groupname));
            }
            
            private Set<String> resolve(final SecurityDynamicConfiguration<?> actionGroups, final String entry) {

                
                // SG5 format, plain array
                //List<String> en = actionGroups.getAsList(DotPath.of(entry));
                //if (en.isEmpty()) {
                    // try SG6 format including readonly and permissions key
                //  en = actionGroups.getAsList(DotPath.of(entry + "." + ConfigConstants.CONFIGKEY_ACTION_GROUPS_PERMISSIONS));
                    //}
                
                if(!actionGroups.getCEntries().containsKey(entry)) {
                    return Collections.emptySet();
                }
                
                final Set<String> ret = new HashSet<String>();
                
                final Object actionGroupAsObject = actionGroups.getCEntries().get(entry);
                
                if(actionGroupAsObject != null && actionGroupAsObject instanceof List) {
                    
                    for (final String perm: ((List<String>) actionGroupAsObject)) {
                        if (actionGroups.getCEntries().keySet().contains(perm)) {
                            ret.addAll(resolve(actionGroups,perm));
                        } else {
                            ret.add(perm);
                        }
                    }
                    
                    
                } else if(actionGroupAsObject != null &&  actionGroupAsObject instanceof ActionGroupsV7) {
                    for (final String perm: ((ActionGroupsV7) actionGroupAsObject).getAllowed_actions()) {
                        if (actionGroups.getCEntries().keySet().contains(perm)) {
                            ret.addAll(resolve(actionGroups,perm));
                        } else {
                            ret.add(perm);
                        }
                    }
                } else {
                    throw new RuntimeException("Unable to handle "+actionGroupAsObject);
                }
                
                return Collections.unmodifiableSet(ret);
            }
            
            @Override
            public Set<String> resolvedActions(final List<String> actions) {
                final Set<String> resolvedActions = new HashSet<String>();
                for (String string: actions) {
                    final Set<String> groups = getGroupMembers(string);
                    if (groups.isEmpty()) {
                        resolvedActions.add(string);
                    } else {
                        resolvedActions.addAll(groups);
                    }
                }

                return Collections.unmodifiableSet(resolvedActions);
            }
        };
    }

    private SecurityRoles reload(SecurityDynamicConfiguration<RoleV7> settings) {

        final Set<Future<SecurityRole>> futures = new HashSet<>(5000);
        final ExecutorService execs = Executors.newFixedThreadPool(10);

        for(Entry<String, RoleV7> securityRole: settings.getCEntries().entrySet()) {

            Future<SecurityRole> future = execs.submit(new Callable<SecurityRole>() {

                @Override
                public SecurityRole call() throws Exception {
                    SecurityRole _securityRole = new SecurityRole(securityRole.getKey());
                    
                    if(securityRole.getValue() == null) {
                        return null;
                    }

                    final Set<String> permittedClusterActions = agr.resolvedActions(securityRole.getValue().getCluster_permissions());
                    _securityRole.addClusterPerms(permittedClusterActions);

                        /*for(RoleV7.Tenant tenant: securityRole.getValue().getTenant_permissions()) {

                            //if(tenant.equals(user.getName())) {
                            //    continue;
                            //}

                            if(isTenantsRw(tenant)) {
                                _securityRole.addTenant(new Tenant(tenant.getKey(), true));
                            } else {
                                _securityRole.addTenant(new Tenant(tenant.getKey(), false));
                            }
                        }*/

                        for (final Index permittedAliasesIndex : securityRole.getValue().getIndex_permissions()) {

                            final String dls = permittedAliasesIndex.getDls();
                            final List<String> fls = permittedAliasesIndex.getFls();
                            final List<String> maskedFields = permittedAliasesIndex.getMasked_fields();

                            for(String pat: permittedAliasesIndex.getIndex_patterns()) {
                                IndexPattern _indexPattern = new IndexPattern(pat);
                                _indexPattern.setDlsQuery(dls);
                                _indexPattern.addFlsFields(fls);
                                _indexPattern.addMaskedFields(maskedFields);
                                _indexPattern.addPerm(agr.resolvedActions(permittedAliasesIndex.getAllowed_actions()));
    
                                /*for(Entry<String, List<String>> type: permittedAliasesIndex.getValue().getTypes(-).entrySet()) {
                                    TypePerm typePerm = new TypePerm(type.getKey());
                                    final List<String> perms = type.getValue();
                                    typePerm.addPerms(agr.resolvedActions(perms));
                                    _indexPattern.addTypePerms(typePerm);
                                }*/
    
                                _securityRole.addIndexPattern(_indexPattern);
                            
                            }

                        }
            
                            
                        return _securityRole;
                }
            });

            futures.add(future);
        }

        execs.shutdown();
        try {
            execs.awaitTermination(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Thread interrupted (1) while loading roles");
            return null;
        }

        try {
            SecurityRoles _securityRoles = new SecurityRoles(futures.size());
            for (Future<SecurityRole> future : futures) {
                _securityRoles.addSecurityRole(future.get());
            }

            return _securityRoles;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Thread interrupted (2) while loading roles");
            return null;
        } catch (ExecutionException e) {
            log.error("Error while updating roles: {}", e.getCause(), e.getCause());
            throw ExceptionsHelper.convertToElastic(e);
        }
    }


    //beans

    public static class SecurityRoles extends com.amazon.opendistroforelasticsearch.security.securityconf.SecurityRoles {

        protected final Logger log = LogManager.getLogger(this.getClass());

        final Set<SecurityRole> roles;

        private SecurityRoles(int roleCount) {
            roles = new HashSet<>(roleCount);
        }

        private SecurityRoles addSecurityRole(SecurityRole securityRole) {
            if (securityRole != null) {
                this.roles.add(securityRole);
            }
            return this;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((roles == null) ? 0 : roles.hashCode());
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
            SecurityRoles other = (SecurityRoles) obj;
            if (roles == null) {
                if (other.roles != null)
                    return false;
            } else if (!roles.equals(other.roles))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "roles=" + roles;
        }

        public Set<SecurityRole> getRoles() {
            return Collections.unmodifiableSet(roles);
        }
        
        public Set<String> getRoleNames() {
            return getRoles().stream().map(r -> r.getName()).collect(Collectors.toSet());
        }

        public SecurityRoles filter(Set<String> keep) {
            final SecurityRoles retVal = new SecurityRoles(roles.size());
            for (SecurityRole sr : roles) {
                if (keep.contains(sr.getName())) {
                    retVal.addSecurityRole(sr);
                }
            }
            return retVal;
        }

        public Map<String, Set<String>> getMaskedFields(User user, IndexNameExpressionResolver resolver, ClusterService cs) {
            final Map<String, Set<String>> maskedFieldsMap = new HashMap<String, Set<String>>();

            for (SecurityRole sr : roles) {
                for (IndexPattern ip : sr.getIpatterns()) {
                    final Set<String> maskedFields = ip.getMaskedFields();
                    final String indexPattern = ip.getUnresolvedIndexPattern(user);
                    String[] concreteIndices = new String[0];

                    if ((maskedFields != null && maskedFields.size() > 0)) {
                        concreteIndices = ip.getResolvedIndexPattern(user, resolver, cs);
                    }

                    if (maskedFields != null && maskedFields.size() > 0) {

                        if (maskedFieldsMap.containsKey(indexPattern)) {
                            maskedFieldsMap.get(indexPattern).addAll(Sets.newHashSet(maskedFields));
                        } else {
                            maskedFieldsMap.put(indexPattern, new HashSet<String>());
                            maskedFieldsMap.get(indexPattern).addAll(Sets.newHashSet(maskedFields));
                        }

                        for (int i = 0; i < concreteIndices.length; i++) {
                            final String ci = concreteIndices[i];
                            if (maskedFieldsMap.containsKey(ci)) {
                                maskedFieldsMap.get(ci).addAll(Sets.newHashSet(maskedFields));
                            } else {
                                maskedFieldsMap.put(ci, new HashSet<String>());
                                maskedFieldsMap.get(ci).addAll(Sets.newHashSet(maskedFields));
                            }
                        }
                    }
                }
            }
            return maskedFieldsMap;
        }

        public Tuple<Map<String, Set<String>>, Map<String, Set<String>>> getDlsFls(User user, IndexNameExpressionResolver resolver,
                ClusterService cs) {

            final Map<String, Set<String>> dlsQueries = new HashMap<String, Set<String>>();
            final Map<String, Set<String>> flsFields = new HashMap<String, Set<String>>();

            for (SecurityRole sr : roles) {
                for (IndexPattern ip : sr.getIpatterns()) {
                    final Set<String> fls = ip.getFls();
                    final String dls = ip.getDlsQuery(user);
                    final String indexPattern = ip.getUnresolvedIndexPattern(user);
                    String[] concreteIndices = new String[0];

                    if ((dls != null && dls.length() > 0) || (fls != null && fls.size() > 0)) {
                        concreteIndices = ip.getResolvedIndexPattern(user, resolver, cs);
                    }

                    if (dls != null && dls.length() > 0) {

                        if (dlsQueries.containsKey(indexPattern)) {
                            dlsQueries.get(indexPattern).add(dls);
                        } else {
                            dlsQueries.put(indexPattern, new HashSet<String>());
                            dlsQueries.get(indexPattern).add(dls);
                        }

                        for (int i = 0; i < concreteIndices.length; i++) {
                            final String ci = concreteIndices[i];
                            if (dlsQueries.containsKey(ci)) {
                                dlsQueries.get(ci).add(dls);
                            } else {
                                dlsQueries.put(ci, new HashSet<String>());
                                dlsQueries.get(ci).add(dls);
                            }
                        }

                    }

                    if (fls != null && fls.size() > 0) {

                        if (flsFields.containsKey(indexPattern)) {
                            flsFields.get(indexPattern).addAll(Sets.newHashSet(fls));
                        } else {
                            flsFields.put(indexPattern, new HashSet<String>());
                            flsFields.get(indexPattern).addAll(Sets.newHashSet(fls));
                        }

                        for (int i = 0; i < concreteIndices.length; i++) {
                            final String ci = concreteIndices[i];
                            if (flsFields.containsKey(ci)) {
                                flsFields.get(ci).addAll(Sets.newHashSet(fls));
                            } else {
                                flsFields.put(ci, new HashSet<String>());
                                flsFields.get(ci).addAll(Sets.newHashSet(fls));
                            }
                        }
                    }
                }
            }

            return new Tuple<Map<String, Set<String>>, Map<String, Set<String>>>(dlsQueries, flsFields);

        }

      //kibana special only, terms eval
        public Set<String> getAllPermittedIndicesForKibana(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
            Set<String> retVal = new HashSet<>();
            for (SecurityRole sr : roles) {
                retVal.addAll(sr.getAllResolvedPermittedIndices(Resolved._LOCAL_ALL, user, actions, resolver, cs));
                retVal.addAll(resolved.getRemoteIndices());
            }
            return Collections.unmodifiableSet(retVal);
        }

        //dnfof only
        public Set<String> reduce(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
            Set<String> retVal = new HashSet<>();
            for (SecurityRole sr : roles) {
                retVal.addAll(sr.getAllResolvedPermittedIndices(resolved, user, actions, resolver, cs));
            }
            if (log.isDebugEnabled()) {
                log.debug("Reduced requested resolved indices {} to permitted indices {}.", resolved, retVal.toString());
            }
            return Collections.unmodifiableSet(retVal);
        }

        //return true on success
        public boolean get(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
            for (SecurityRole sr : roles) {
                if (ConfigModelV7.impliesTypePerm(sr.getIpatterns(), resolved, user, actions, resolver, cs)) {
                    return true;
                }
            }
            return false;
        }

        public boolean impliesClusterPermissionPermission(String action) {
            return roles.stream().filter(r -> r.impliesClusterPermission(action)).count() > 0;
        }

        //rolespan
        public boolean impliesTypePermGlobal(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver,
                ClusterService cs) {
            Set<IndexPattern> ipatterns = new HashSet<ConfigModelV7.IndexPattern>();
            roles.stream().forEach(p -> ipatterns.addAll(p.getIpatterns()));
            return ConfigModelV7.impliesTypePerm(ipatterns, resolved, user, actions, resolver, cs);
        }
    }

    public static class SecurityRole {

        private final String name;
        //private final Set<Tenant> tenants = new HashSet<>();
        private final Set<IndexPattern> ipatterns = new HashSet<>();
        private final Set<String> clusterPerms = new HashSet<>();

        private SecurityRole(String name) {
            super();
            this.name = Objects.requireNonNull(name);
        }

        private boolean impliesClusterPermission(String action) {
            return WildcardMatcher.matchAny(clusterPerms, action);
        }

        //get indices which are permitted for the given types and actions
        //dnfof + kibana special only
        private Set<String> getAllResolvedPermittedIndices(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver,
                ClusterService cs) {

            final Set<String> retVal = new HashSet<>();
            for (IndexPattern p : ipatterns) {
                //what if we cannot resolve one (for create purposes)
                final boolean patternMatch = WildcardMatcher.matchAll(p.getPerms().toArray(new String[0]), actions);
                
//                final Set<TypePerm> tperms = p.getTypePerms();
//                for (TypePerm tp : tperms) {
//                    if (WildcardMatcher.matchAny(tp.typePattern, resolved.getTypes(-).toArray(new String[0]))) {
//                        patternMatch = WildcardMatcher.matchAll(tp.perms.toArray(new String[0]), actions);
//                    }
//                }
                if (patternMatch) {
                    //resolved but can contain patterns for nonexistent indices
                    final String[] permitted = p.getResolvedIndexPattern(user, resolver, cs); //maybe they do not exist
                    final Set<String> res = new HashSet<>();
                    if (!resolved.isLocalAll() && !resolved.getAllIndices().contains("*") && !resolved.getAllIndices().contains("_all")) {
                        final Set<String> wanted = new HashSet<>(resolved.getAllIndices());
                        //resolved but can contain patterns for nonexistent indices
                        WildcardMatcher.wildcardRetainInSet(wanted, permitted);
                        res.addAll(wanted);
                    } else {
                        //we want all indices so just return what's permitted

                        //#557
                        //final String[] allIndices = resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), "*");
                        final String[] allIndices = cs.state().metaData().getConcreteAllOpenIndices();
                        final Set<String> wanted = new HashSet<>(Arrays.asList(allIndices));
                        WildcardMatcher.wildcardRetainInSet(wanted, permitted);
                        res.addAll(wanted);
                    }
                    retVal.addAll(res);
                }
            }

            //all that we want and all thats permitted of them
            return Collections.unmodifiableSet(retVal);
        }

        /*private SecurityRole addTenant(Tenant tenant) {
            if (tenant != null) {
                this.tenants.add(tenant);
            }
            return this;
        }*/

        private SecurityRole addIndexPattern(IndexPattern indexPattern) {
            if (indexPattern != null) {
                this.ipatterns.add(indexPattern);
            }
            return this;
        }

        private SecurityRole addClusterPerms(Collection<String> clusterPerms) {
            if (clusterPerms != null) {
                this.clusterPerms.addAll(clusterPerms);
            }
            return this;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((clusterPerms == null) ? 0 : clusterPerms.hashCode());
            result = prime * result + ((ipatterns == null) ? 0 : ipatterns.hashCode());
            result = prime * result + ((name == null) ? 0 : name.hashCode());
            //result = prime * result + ((tenants == null) ? 0 : tenants.hashCode());
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
            SecurityRole other = (SecurityRole) obj;
            if (clusterPerms == null) {
                if (other.clusterPerms != null)
                    return false;
            } else if (!clusterPerms.equals(other.clusterPerms))
                return false;
            if (ipatterns == null) {
                if (other.ipatterns != null)
                    return false;
            } else if (!ipatterns.equals(other.ipatterns))
                return false;
            if (name == null) {
                if (other.name != null)
                    return false;
            } else if (!name.equals(other.name))
                return false;
//            if (tenants == null) {
//                if (other.tenants != null)
//                    return false;
//            } else if (!tenants.equals(other.tenants))
//                return false;
            return true;
        }

        @Override
        public String toString() {
            return System.lineSeparator() + "  " + name + System.lineSeparator()
                    + "    ipatterns=" + ipatterns + System.lineSeparator() + "    clusterPerms=" + clusterPerms;
        }

        //public Set<Tenant> getTenants(User user) {
        //    //TODO filter out user tenants
        //    return Collections.unmodifiableSet(tenants);
        //}

        public Set<IndexPattern> getIpatterns() {
            return Collections.unmodifiableSet(ipatterns);
        }

        public Set<String> getClusterPerms() {
            return Collections.unmodifiableSet(clusterPerms);
        }

        public String getName() {
            return name;
        }

    }

    //sg roles
    public static class IndexPattern {
        private final String indexPattern;
        private String dlsQuery;
        private final Set<String> fls = new HashSet<>();
        private final Set<String> maskedFields = new HashSet<>();
        private final Set<String> perms = new HashSet<>();

        public IndexPattern(String indexPattern) {
            super();
            this.indexPattern = Objects.requireNonNull(indexPattern);
        }

        public IndexPattern addFlsFields(List<String> flsFields) {
            if (flsFields != null) {
                this.fls.addAll(flsFields);
            }
            return this;
        }

        public IndexPattern addMaskedFields(List<String> maskedFields) {
            if (maskedFields != null) {
                this.maskedFields.addAll(maskedFields);
            }
            return this;
        }

        public IndexPattern addPerm(Set<String> perms) {
            if (perms != null) {
                this.perms.addAll(perms);
            }
            return this;
        }

        public IndexPattern setDlsQuery(String dlsQuery) {
            if (dlsQuery != null) {
                this.dlsQuery = dlsQuery;
            }
            return this;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((dlsQuery == null) ? 0 : dlsQuery.hashCode());
            result = prime * result + ((fls == null) ? 0 : fls.hashCode());
            result = prime * result + ((maskedFields == null) ? 0 : maskedFields.hashCode());
            result = prime * result + ((indexPattern == null) ? 0 : indexPattern.hashCode());
            result = prime * result + ((perms == null) ? 0 : perms.hashCode());
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
            IndexPattern other = (IndexPattern) obj;
            if (dlsQuery == null) {
                if (other.dlsQuery != null)
                    return false;
            } else if (!dlsQuery.equals(other.dlsQuery))
                return false;
            if (fls == null) {
                if (other.fls != null)
                    return false;
            } else if (!fls.equals(other.fls))
                return false;
            if (maskedFields == null) {
                if (other.maskedFields != null)
                    return false;
            } else if (!maskedFields.equals(other.maskedFields))
                return false;
            if (indexPattern == null) {
                if (other.indexPattern != null)
                    return false;
            } else if (!indexPattern.equals(other.indexPattern))
                return false;
            if (perms == null) {
                if (other.perms != null)
                    return false;
            } else if (!perms.equals(other.perms))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return System.lineSeparator() + "        indexPattern=" + indexPattern + System.lineSeparator() + "          dlsQuery=" + dlsQuery
                    + System.lineSeparator() + "          fls=" + fls + System.lineSeparator() + "          perms=" + perms;
        }

        public String getUnresolvedIndexPattern(User user) {
            return replaceProperties(indexPattern, user);
        }

        private String[] getResolvedIndexPattern(User user, IndexNameExpressionResolver resolver, ClusterService cs) {
            String unresolved = getUnresolvedIndexPattern(user);
            String[] resolved = null;
            if (WildcardMatcher.containsWildcard(unresolved)) {
                final String[] aliasesForPermittedPattern = cs.state().getMetaData().getAliasAndIndexLookup().entrySet().stream()
                        .filter(e -> e.getValue().isAlias()).filter(e -> WildcardMatcher.match(unresolved, e.getKey())).map(e -> e.getKey())
                        .toArray(String[]::new);

                if (aliasesForPermittedPattern != null && aliasesForPermittedPattern.length > 0) {
                    resolved = resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), aliasesForPermittedPattern);
                }
            }

            if (resolved == null && !unresolved.isEmpty()) {
                resolved = resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), unresolved);
            }
            if (resolved == null || resolved.length == 0) {
                return new String[] { unresolved };
            } else {
                //append unresolved value for pattern matching
                String[] retval = Arrays.copyOf(resolved, resolved.length + 1);
                retval[retval.length - 1] = unresolved;
                return retval;
            }
        }

        public String getDlsQuery(User user) {
            return replaceProperties(dlsQuery, user);
        }

        public Set<String> getFls() {
            return Collections.unmodifiableSet(fls);
        }

        public Set<String> getMaskedFields() {
            return Collections.unmodifiableSet(maskedFields);
        }

        public Set<String> getPerms() {
            return Collections.unmodifiableSet(perms);
        }

    }

    /*public static class TypePerm {
        private final String typePattern;
        private final Set<String> perms = new HashSet<>();

        private TypePerm(String typePattern) {
            super();
            this.typePattern = Objects.requireNonNull(typePattern);
            /*if(IGNORED_TYPES.contains(typePattern)) {
                throw new RuntimeException("typepattern '"+typePattern+"' not allowed");
            }
        }

        private TypePerm addPerms(Collection<String> perms) {
            if (perms != null) {
                this.perms.addAll(perms);
            }
            return this;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((perms == null) ? 0 : perms.hashCode());
            result = prime * result + ((typePattern == null) ? 0 : typePattern.hashCode());
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
            TypePerm other = (TypePerm) obj;
            if (perms == null) {
                if (other.perms != null)
                    return false;
            } else if (!perms.equals(other.perms))
                return false;
            if (typePattern == null) {
                if (other.typePattern != null)
                    return false;
            } else if (!typePattern.equals(other.typePattern))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return System.lineSeparator() + "             typePattern=" + typePattern + System.lineSeparator() + "             perms=" + perms;
        }

        public String getTypePattern() {
            return typePattern;
        }

        public Set<String> getPerms() {
            return Collections.unmodifiableSet(perms);
        }

    }*/

    public static class Tenant {
        private final String tenant;
        private final boolean readWrite;

        private Tenant(String tenant, boolean readWrite) {
            super();
            this.tenant = tenant;
            this.readWrite = readWrite;
        }

        public String getTenant() {
            return tenant;
        }

        public boolean isReadWrite() {
            return readWrite;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + (readWrite ? 1231 : 1237);
            result = prime * result + ((tenant == null) ? 0 : tenant.hashCode());
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
            Tenant other = (Tenant) obj;
            if (readWrite != other.readWrite)
                return false;
            if (tenant == null) {
                if (other.tenant != null)
                    return false;
            } else if (!tenant.equals(other.tenant))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return System.lineSeparator() + "                tenant=" + tenant + System.lineSeparator() + "                readWrite=" + readWrite;
        }
    }

    private static String replaceProperties(String orig, User user) {

        if (user == null || orig == null) {
            return orig;
        }

        orig = orig.replace("${user.name}", user.getName()).replace("${user_name}", user.getName());
        orig = replaceRoles(orig, user);
        for (Entry<String, String> entry : user.getCustomAttributesMap().entrySet()) {
            if (entry == null || entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            orig = orig.replace("${" + entry.getKey() + "}", entry.getValue());
            orig = orig.replace("${" + entry.getKey().replace('.', '_') + "}", entry.getValue());
        }
        return orig;
    }

    private static String replaceRoles(final String orig, final User user) {
        String retVal = orig;
        if (orig.contains("${user.roles}") || orig.contains("${user_roles}")) {
            final String commaSeparatedRoles = toQuotedCommaSeparatedString(user.getRoles());
            retVal = orig.replace("${user.roles}", commaSeparatedRoles).replace("${user_roles}", commaSeparatedRoles);
        }
        return retVal;
    }

    private static String toQuotedCommaSeparatedString(final Set<String> roles) {
        return Joiner.on(',').join(Iterables.transform(roles, s -> {
            return new StringBuilder(s.length() + 2).append('"').append(s).append('"').toString();
        }));
    }

    private static boolean impliesTypePerm(Set<IndexPattern> ipatterns, Resolved resolved, User user, String[] actions,
            IndexNameExpressionResolver resolver, ClusterService cs) {
        Set<String> matchingIndex = new HashSet<>(resolved.getAllIndices());

        for (String in : resolved.getAllIndices()) {
            //find index patterns who are matching
            Set<String> matchingActions = new HashSet<>(Arrays.asList(actions));
            //Set<String> matchingTypes = new HashSet<>(resolved.getTypes(-));
            for (IndexPattern p : ipatterns) {
                if (WildcardMatcher.matchAny(p.getResolvedIndexPattern(user, resolver, cs), in)) {
                    //per resolved index per pattern
                    //for (String t : resolved.getTypes(-)) {
                        //for (TypePerm tp : p.typePerms) {
                            //if (WildcardMatcher.match(tp.typePattern, t)) {
                                //matchingTypes.remove(t);
                                for (String a : Arrays.asList(actions)) {
                                    if (WildcardMatcher.matchAny(p.perms, a)) {
                                        matchingActions.remove(a);
                                    }
                                }
                            //}
                        //}
                    //}
                }
            }

            if (matchingActions.isEmpty() /*&& matchingTypes.isEmpty()*/) {
                matchingIndex.remove(in);
            }
        }

        return matchingIndex.isEmpty();
    }
    
    
    
    //#######
    
    private class TenantHolder {

        private SetMultimap<String, Tuple<String, Boolean>> tenantsMM = null;

        public TenantHolder(SecurityDynamicConfiguration<RoleV7> roles, SecurityDynamicConfiguration<TenantV7> definedTenants) {
            final Set<Future<Tuple<String, Set<Tuple<String, Boolean>>>>> futures = new HashSet<>(roles.getCEntries().size());

            final ExecutorService execs = Executors.newFixedThreadPool(10);

            for(Entry<String, RoleV7> securityRole: roles.getCEntries().entrySet()) {
                
                if(securityRole.getValue() == null) {
                    continue;
                }

                Future<Tuple<String, Set<Tuple<String, Boolean>>>> future = execs.submit(new Callable<Tuple<String, Set<Tuple<String, Boolean>>>>() {
                    @Override
                    public Tuple<String, Set<Tuple<String, Boolean>>> call() throws Exception {
                        final Set<Tuple<String, Boolean>> tuples = new HashSet<>();
                        final List<RoleV7.Tenant> tenants = securityRole.getValue().getTenant_permissions();

                        if (tenants != null) {
                            
                            for (RoleV7.Tenant tenant : tenants) {
                                
                                for(String matchingTenant: WildcardMatcher.getMatchAny(tenant.getTenant_patterns(), definedTenants.getCEntries().keySet())) {
                                    tuples.add(new Tuple<String, Boolean>(matchingTenant, agr.resolvedActions(tenant.getAllowed_actions()).contains("kibana:saved_objects/*/write")));
                                }
                            }
                        }

                        return new Tuple<String, Set<Tuple<String, Boolean>>>(securityRole.getKey(), tuples);
                    }
                });

                futures.add(future);

            }

            execs.shutdown();
            try {
                execs.awaitTermination(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (1) while loading roles");
                return;
            }

            try {
                final SetMultimap<String, Tuple<String, Boolean>> tenantsMM_ = SetMultimapBuilder.hashKeys(futures.size()).hashSetValues(16).build();

                for (Future<Tuple<String, Set<Tuple<String, Boolean>>>> future : futures) {
                    Tuple<String, Set<Tuple<String, Boolean>>> result = future.get();
                    tenantsMM_.putAll(result.v1(), result.v2());
                }

                tenantsMM = tenantsMM_;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted (2) while loading roles");
                return;
            } catch (ExecutionException e) {
                log.error("Error while updating roles: {}", e.getCause(), e.getCause());
                throw ExceptionsHelper.convertToElastic(e);
            }

        }

        public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {

            if (user == null || tenantsMM == null) {
                return Collections.emptyMap();
            }

            final Map<String, Boolean> result = new HashMap<>(roles.size());
            result.put(user.getName(), true);

            tenantsMM.entries().stream().filter(e -> roles.contains(e.getKey())).filter(e -> !user.getName().equals(e.getValue().v1())).forEach(e -> {
                final String tenant = e.getValue().v1();
                final boolean rw = e.getValue().v2();

                if (rw || !result.containsKey(tenant)) { //RW outperforms RO
                    result.put(tenant, rw);
                }
            });
            
            if(!result.containsKey("global_tenant") && (
                    roles.contains("kibana_user")
                    || roles.contains("kibana_user")
                    || roles.contains("all_access")
                    || roles.contains("ALL_ACCESS")
                    )) {
                result.put("global_tenant", true);
            }

            return Collections.unmodifiableMap(result);
        }
    }

    private class RoleMappingHolder {

        private ListMultimap<String, String> users;
        private ListMultimap<Set<String>, String> abars;
        private ListMultimap<String, String> bars;
        private ListMultimap<String, String> hosts;
        private final String hostResolverMode;

        private RoleMappingHolder(final SecurityDynamicConfiguration<RoleMappingsV7> rolemappings, final String hostResolverMode) {

            this.hostResolverMode = hostResolverMode;
            
            if (roles != null) {

                final ListMultimap<String, String> users_ = ArrayListMultimap.create();
                final ListMultimap<Set<String>, String> abars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> bars_ = ArrayListMultimap.create();
                final ListMultimap<String, String> hosts_ = ArrayListMultimap.create();

                for (final Entry<String, RoleMappingsV7> roleMap : rolemappings.getCEntries().entrySet()) {

                    for (String u : roleMap.getValue().getUsers()) {
                        users_.put(u, roleMap.getKey());
                    }

                    final Set<String> abar = new HashSet<String>(roleMap.getValue().getAnd_backend_roles());

                    if (!abar.isEmpty()) {
                        abars_.put(abar, roleMap.getKey());
                    }

                    for (String bar : roleMap.getValue().getBackend_roles()) {
                        bars_.put(bar, roleMap.getKey());
                    }

                    for (String host : roleMap.getValue().getHosts()) {
                        hosts_.put(host, roleMap.getKey());
                    }
                }

                users = users_;
                abars = abars_;
                bars = bars_;
                hosts = hosts_;
            }
        }

        private Set<String> map(final User user, final TransportAddress caller) {

            if (user == null || users == null || abars == null || bars == null || hosts == null) {
                return Collections.emptySet();
            }

            final Set<String> securityRoles = new TreeSet<String>(user.getOpenDistroSecurityRoles());

            if (rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
                if (log.isDebugEnabled()) {
                    log.debug("Pass backendroles from {}", user);
                }
                securityRoles.addAll(user.getRoles());
            }

            if (((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                    || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {

                for (String p : WildcardMatcher.getAllMatchingPatterns(users.keySet(), user.getName())) {
                    securityRoles.addAll(users.get(p));
                }

                for (String p : WildcardMatcher.getAllMatchingPatterns(bars.keySet(), user.getRoles())) {
                    securityRoles.addAll(bars.get(p));
                }

                for (Set<String> p : abars.keySet()) {
                    if (WildcardMatcher.allPatternsMatched(p, user.getRoles())) {
                        securityRoles.addAll(abars.get(p));
                    }
                }

                if (caller != null) {
                    //IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();

                    for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), ipAddress)) {
                        securityRoles.addAll(hosts.get(p));
                    }

                    if (caller.address() != null
                            && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))) {
                        final String hostName = caller.address().getHostString();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), hostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }

                    if (caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")) {

                        final String resolvedHostName = caller.address().getHostName();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hosts.keySet(), resolvedHostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }
                }
            }

            return Collections.unmodifiableSet(securityRoles);

        }
    }
    
    
    
    

    public Map<String, Boolean> mapTenants(User user, Set<String> roles) {
        return tenantHolder.mapTenants(user, roles);
    }

    public Set<String> mapSecurityRoles(User user, TransportAddress caller) {
        return roleMappingHolder.map(user, caller);
    }
}
