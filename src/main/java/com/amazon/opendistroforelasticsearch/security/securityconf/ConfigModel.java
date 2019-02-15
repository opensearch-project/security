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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.configuration.ActionGroupHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;

public class ConfigModel {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private static final Set<String> IGNORED_TYPES = ImmutableSet.of("_dls_", "_fls_","_masked_fields_");
    private final ActionGroupHolder ah;
    private final ConfigurationRepository configurationRepository;

    public ConfigModel(final ActionGroupHolder ah,
            final ConfigurationRepository configurationRepository) {
        super();
        this.ah = ah;
        this.configurationRepository = configurationRepository;
    }

    public SecurityRoles load() {
        final Settings settings = configurationRepository.getConfiguration("roles", false);
        SecurityRoles _securityRoles = new SecurityRoles();
        Set<String> securityRoles = settings.names();
        for(String securityRole: securityRoles) {

            SecurityRole _securityRole = new SecurityRole(securityRole);

            final Settings securityRoleSettings = settings.getByPrefix(securityRole);
            if (securityRoleSettings.names().isEmpty()) {
                continue;
            }

            final Set<String> permittedClusterActions = ah.resolvedActions(securityRoleSettings.getAsList(".cluster", Collections.emptyList()));
            _securityRole.addClusterPerms(permittedClusterActions);

            Settings tenants = settings.getByPrefix(securityRole+".tenants.");

            if(tenants != null) {
                for(String tenant: tenants.names()) {

                    //if(tenant.equals(user.getName())) {
                    //    continue;
                    //}

                    if("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                        _securityRole.addTenant(new Tenant(tenant, true));
                    } else {
                        _securityRole.addTenant(new Tenant(tenant, false));
                        //if(_securityRole.tenants.stream().filter(t->t.tenant.equals(tenant)).count() > 0) { //RW outperforms RO
                        //    _securityRole.addTenant(new Tenant(tenant, false));
                        //}
                    }
                }
            }


            final Map<String, Settings> permittedAliasesIndices = securityRoleSettings.getGroups(".indices");

            for (final String permittedAliasesIndex : permittedAliasesIndices.keySet()) {

                final String resolvedRole = securityRole;
                final String indexPattern = permittedAliasesIndex;

                final String dls = settings.get(resolvedRole+".indices."+indexPattern+"._dls_");
                final List<String> fls = settings.getAsList(resolvedRole+".indices."+indexPattern+"._fls_");
                final List<String> maskedFields = settings.getAsList(resolvedRole+".indices."+indexPattern+"._masked_fields_");

                IndexPattern _indexPattern = new IndexPattern(indexPattern);
                _indexPattern.setDlsQuery(dls);
                _indexPattern.addFlsFields(fls);
                _indexPattern.addMaskedFields(maskedFields);

                for(String type: permittedAliasesIndices.get(indexPattern).names()) {

                    if(IGNORED_TYPES.contains(type)) {
                        continue;
                    }

                    TypePerm typePerm = new TypePerm(type);
                    final List<String> perms = settings.getAsList(resolvedRole+".indices."+indexPattern+"."+type);
                    typePerm.addPerms(ah.resolvedActions(perms));
                    _indexPattern.addTypePerms(typePerm);
                }

                _securityRole.addIndexPattern(_indexPattern);

            }
            _securityRoles.addSecurityRole(_securityRole);
        }

        return _securityRoles;
    }

    //beans

    public static class SecurityRoles {

        protected final Logger log = LogManager.getLogger(this.getClass());
        
        final Set<SecurityRole> roles = new HashSet<>(100);

        private SecurityRoles() {
        }

        private SecurityRoles addSecurityRole(SecurityRole securityRole) {
            if(securityRole != null) {
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

        public SecurityRoles filter(Set<String> keep) {
            final SecurityRoles retVal = new SecurityRoles();
            for(SecurityRole sgr: roles) {
                if(keep.contains(sgr.getName())) {
                    retVal.addSecurityRole(sgr);
                }
            }
            return retVal;
        }
        
        public Map<String,Set<String>> getMaskedFields(User user, IndexNameExpressionResolver resolver, ClusterService cs) {
            final Map<String,Set<String>> maskedFieldsMap = new HashMap<String, Set<String>>();
            
            for(SecurityRole sgr: roles) {
                for(IndexPattern ip: sgr.getIpatterns()) {
                    final Set<String> maskedFields = ip.getMaskedFields();
                    final String indexPattern = ip.getUnresolvedIndexPattern(user);
                    String[] concreteIndices = new String[0];

                    if((maskedFields != null && maskedFields.size() > 0)) {
                        concreteIndices = ip.getResolvedIndexPattern(user, resolver, cs);
                    }

                    if(maskedFields != null && maskedFields.size() > 0) {

                        if(maskedFieldsMap.containsKey(indexPattern)) {
                            maskedFieldsMap.get(indexPattern).addAll(Sets.newHashSet(maskedFields));
                        } else {
                            maskedFieldsMap.put(indexPattern, new HashSet<String>());
                            maskedFieldsMap.get(indexPattern).addAll(Sets.newHashSet(maskedFields));
                        }

                        for (int i = 0; i < concreteIndices.length; i++) {
                            final String ci = concreteIndices[i];
                            if(maskedFieldsMap.containsKey(ci)) {
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

        public Tuple<Map<String,Set<String>>,Map<String,Set<String>>> getDlsFls(User user, IndexNameExpressionResolver resolver, ClusterService cs) {

            final Map<String,Set<String>> dlsQueries = new HashMap<String, Set<String>>();
            final Map<String,Set<String>> flsFields = new HashMap<String, Set<String>>();

            for(SecurityRole sgr: roles) {
                for(IndexPattern ip: sgr.getIpatterns()) {
                    final Set<String> fls = ip.getFls();
                    final String dls = ip.getDlsQuery(user);
                    final String indexPattern = ip.getUnresolvedIndexPattern(user);
                    String[] concreteIndices = new String[0];

                    if((dls != null && dls.length() > 0) || (fls != null && fls.size() > 0)) {
                        concreteIndices = ip.getResolvedIndexPattern(user, resolver, cs);
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
                    }
                }
            }

            return new Tuple<Map<String,Set<String>>, Map<String,Set<String>>>(dlsQueries, flsFields);

        }
        
        //kibana special only
        public Set<String> getAllPermittedIndices(User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
            Set<String> retVal = new HashSet<>();
            for(SecurityRole sgr: roles) {
                retVal.addAll(sgr.getAllResolvedPermittedIndices(Resolved._ALL, user, actions, resolver, cs));
            }
            return Collections.unmodifiableSet(retVal);
        }

        //dnfof only
        public Set<String> reduce(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
            Set<String> retVal = new HashSet<>();
            for(SecurityRole sgr: roles) {
                retVal.addAll(sgr.getAllResolvedPermittedIndices(resolved, user, actions, resolver, cs));
            }
            if(log.isDebugEnabled()) {
                log.debug("Reduced requested resolved indices {} to permitted indices {}.", resolved, retVal.toString());
            }
            return Collections.unmodifiableSet(retVal);
        }

        //return true on success
        public boolean get(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
            for(SecurityRole sgr: roles) {
                if(ConfigModel.impliesTypePerm(sgr.getIpatterns(), resolved, user, actions, resolver, cs)) {
                    return true;
                }
            }
            return false;
        }

        public boolean impliesClusterPermissionPermission(String action) {
            return roles.stream()
                    .filter(r->r.impliesClusterPermission(action)).count() > 0;
        }
        
        //rolespan
        public boolean impliesTypePermGlobal(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
            Set<IndexPattern> ipatterns = new HashSet<ConfigModel.IndexPattern>();
            roles.stream().forEach(p->ipatterns.addAll(p.getIpatterns()));
            return ConfigModel.impliesTypePerm(ipatterns, resolved, user, actions, resolver, cs);
        }  
    }

    public static class SecurityRole {

        private final String name;
        private final Set<Tenant> tenants = new HashSet<>();
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
        private Set<String> getAllResolvedPermittedIndices(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {

            final Set<String> retVal = new HashSet<>();
            for(IndexPattern p: ipatterns) {
               //what if we cannot resolve one (for create purposes)
               boolean patternMatch = false;
               final Set<TypePerm> tperms = p.getTypePerms();
               for(TypePerm tp: tperms) {
                   if(WildcardMatcher.matchAny(tp.typePattern, resolved.getTypes().toArray(new String[0]))) {
                       patternMatch = WildcardMatcher.matchAll(tp.perms.toArray(new String[0]), actions);
                   }
               }
               if(patternMatch) {
                   //resolved but can contain patterns for nonexistent indices
                   final String[] permitted = p.getResolvedIndexPattern(user, resolver, cs); //maybe they do not exists
                   final Set<String> res = new HashSet<>();
                   if(!resolved.isAll() && !resolved.getAllIndices().contains("*")  && !resolved.getAllIndices().contains("_all")) {
                       final Set<String> wanted = new HashSet<>(resolved.getAllIndices());
                       //resolved but can contain patterns for nonexistent indices
                       WildcardMatcher.wildcardRetainInSet(wanted, permitted);
                       res.addAll(wanted);
                   } else {
                       //we want all indices so just return what's permitted
                       
                       //#557
                       final String[] allIndices = resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), "*");
                       final Set<String> wanted = new HashSet<>(Arrays.asList(allIndices));
                       WildcardMatcher.wildcardRetainInSet(wanted, permitted);
                       res.addAll(wanted);
                       //res.addAll(Arrays.asList(resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), permitted)));
                   }
                   retVal.addAll(res);
               }
            }

            //all that we want and all thats permitted of them
            return Collections.unmodifiableSet(retVal);
        }

        

        private SecurityRole addTenant(Tenant tenant) {
            if(tenant != null) {
                this.tenants.add(tenant);
            }
            return this;
        }

        private SecurityRole addIndexPattern(IndexPattern indexPattern) {
            if(indexPattern != null) {
                this.ipatterns.add(indexPattern);
            }
            return this;
        }

        private SecurityRole addClusterPerms(Collection<String> clusterPerms) {
            if(clusterPerms != null) {
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
            result = prime * result + ((tenants == null) ? 0 : tenants.hashCode());
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
            if (tenants == null) {
                if (other.tenants != null)
                    return false;
            } else if (!tenants.equals(other.tenants))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return System.lineSeparator()+"  "+name+System.lineSeparator()+"    tenants=" + tenants + System.lineSeparator()+ "    ipatterns=" + ipatterns + System.lineSeparator()+ "    clusterPerms=" + clusterPerms;
        }

        public Set<Tenant> getTenants(User user) {
            //TODO filter out user tenants
            return Collections.unmodifiableSet(tenants);
        }

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

    //Security roles
    public static class IndexPattern {
        private final String indexPattern;
        private String dlsQuery;
        private final Set<String> fls = new HashSet<>();
        private final Set<String> maskedFields = new HashSet<>();
        private final Set<TypePerm> typePerms = new HashSet<>();

        public IndexPattern(String indexPattern) {
            super();
            this.indexPattern = Objects.requireNonNull(indexPattern);
        }

        public IndexPattern addFlsFields(List<String> flsFields) {
            if(flsFields != null) {
                this.fls.addAll(flsFields);
            }
            return this;
        }
        
        public IndexPattern addMaskedFields(List<String> maskedFields) {
            if(maskedFields != null) {
                this.maskedFields.addAll(maskedFields);
            }
            return this;
        }

        public IndexPattern addTypePerms(TypePerm typePerm) {
            if(typePerm != null) {
                this.typePerms.add(typePerm);
            }
            return this;
        }

        public IndexPattern setDlsQuery(String dlsQuery) {
            if(dlsQuery != null) {
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
            result = prime * result + ((typePerms == null) ? 0 : typePerms.hashCode());
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
            if (typePerms == null) {
                if (other.typePerms != null)
                    return false;
            } else if (!typePerms.equals(other.typePerms))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return System.lineSeparator()+"        indexPattern=" + indexPattern + System.lineSeparator()+"          dlsQuery=" + dlsQuery + System.lineSeparator()+ "          fls=" + fls + System.lineSeparator()+ "          typePerms=" + typePerms;
        }

        public String getUnresolvedIndexPattern(User user) {
            return replaceProperties(indexPattern, user);
        }

        private String[] getResolvedIndexPattern(User user, IndexNameExpressionResolver resolver, ClusterService cs) {
            String unresolved = getUnresolvedIndexPattern(user);
            String[] resolved = null;
            if(WildcardMatcher.containsWildcard(unresolved)) {
                final String[] aliasesForPermittedPattern = cs.state().getMetaData().getAliasAndIndexLookup()        
                        .entrySet().stream()
                        .filter(e->e.getValue().isAlias())
                        .filter(e->WildcardMatcher.match(unresolved, e.getKey()))
                        .map(e->e.getKey()).toArray(String[]::new);
                
                if(aliasesForPermittedPattern != null && aliasesForPermittedPattern.length > 0) {
                    resolved = resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), aliasesForPermittedPattern);
                }
            }
            
            if(resolved == null && !unresolved.isEmpty()) {
                resolved = resolver.concreteIndexNames(cs.state(), IndicesOptions.lenientExpandOpen(), unresolved);
            }
            if(resolved == null || resolved.length == 0) {
                return new String[]{unresolved};
            } else {
                //append unresolved value for pattern matching
                String[] retval = Arrays.copyOf(resolved, resolved.length +1);
                retval[retval.length-1] = unresolved;
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

        public Set<TypePerm> getTypePerms() {
            return Collections.unmodifiableSet(typePerms);
        }



    }

    public static class TypePerm {
        private final String typePattern;
        private final Set<String> perms = new HashSet<>();

        private TypePerm(String typePattern) {
            super();
            this.typePattern = Objects.requireNonNull(typePattern);
            if(IGNORED_TYPES.contains(typePattern)) {
                throw new RuntimeException("typepattern '"+typePattern+"' not allowed");
            }
        }

        private TypePerm addPerms(Collection<String> perms) {
            if(perms != null) {
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
            return System.lineSeparator()+"             typePattern=" + typePattern + System.lineSeparator()+ "             perms=" + perms;
        }

        public String getTypePattern() {
            return typePattern;
        }

        public Set<String> getPerms() {
            return Collections.unmodifiableSet(perms);
        }

    }

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
            return System.lineSeparator()+"                tenant=" + tenant + System.lineSeparator() +"                readWrite=" + readWrite;
        }
    }

    
    private static String replaceProperties(String orig, User user) {
        
        if(user == null || orig == null) {
            return orig;
        }
        
        orig = orig.replace("${user.name}", user.getName()).replace("${user_name}", user.getName());
        orig = replaceRoles(orig, user);
        for(Entry<String, String> entry: user.getCustomAttributesMap().entrySet()) {
            if(entry == null || entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            orig = orig.replace("${"+entry.getKey()+"}", entry.getValue());
            orig = orig.replace("${"+entry.getKey().replace('.', '_')+"}", entry.getValue());
        }
        return orig;
    }
    
    private static String replaceRoles(final String orig, final User user) {
        String retVal = orig;
        if(orig.contains("${user.roles}") || orig.contains("${user_roles}")) {
            final String commaSeparatedRoles = toQuotedCommaSeparatedString(user.getRoles());
            retVal = orig.replace("${user.roles}", commaSeparatedRoles).replace("${user_roles}", commaSeparatedRoles);
        }
        return retVal;
    }
    
    private static String toQuotedCommaSeparatedString(final Set<String> roles) {
        return Joiner.on(',').join(Iterables.transform(roles, s->{
            return new StringBuilder(s.length()+2).append('"').append(s).append('"').toString();
        }));
    }
    
    private static boolean impliesTypePerm(Set<IndexPattern> ipatterns, Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs) {
        Set<String> matchingIndex = new HashSet<>(resolved.getAllIndices());

        for(String in: resolved.getAllIndices()) {
            //find index patterns who are matching
            Set<String> matchingActions = new HashSet<>(Arrays.asList(actions));
            Set<String> matchingTypes = new HashSet<>(resolved.getTypes());
            for(IndexPattern p: ipatterns) {
                if(WildcardMatcher.matchAny(p.getResolvedIndexPattern(user, resolver, cs), in)) {
                    //per resolved index per pattern
                    for(String t: resolved.getTypes()) {
                        for(TypePerm tp: p.typePerms) {
                            if(WildcardMatcher.match(tp.typePattern, t)) {
                                matchingTypes.remove(t);
                                for(String a: Arrays.asList(actions)) {
                                    if(WildcardMatcher.matchAny(tp.perms, a)) {
                                        matchingActions.remove(a);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if(matchingActions.isEmpty() && matchingTypes.isEmpty()) {
                matchingIndex.remove(in);
            }
        }

        return matchingIndex.isEmpty();
    }
}
