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

package org.opensearch.security.securityconf;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.MultimapBuilder.SetMultimapBuilder;
import com.google.common.collect.SetMultimap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.privileges.UserAttributes;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

public class ConfigModelV7 extends ConfigModel {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private ConfigConstants.RolesMappingResolution rolesMappingResolution;
    private FlattenedActionGroups actionGroups;
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
        Settings opensearchSettings
    ) {

        this.roles = roles;
        this.tenants = tenants;

        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(
                opensearchSettings.get(
                    ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION,
                    ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString()
                ).toUpperCase()
            );
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution", e);
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }

        actionGroups = actiongroups != null ? new FlattenedActionGroups(actiongroups) : FlattenedActionGroups.EMPTY;
        tenantHolder = new TenantHolder(roles, tenants);
        roleMappingHolder = new RoleMappingHolder(rolemappings, dcm.getHostsResolverMode());
    }

    public Set<String> getAllConfiguredTenantNames() {
        return Collections.unmodifiableSet(tenants.getCEntries().keySet());
    }

    private class TenantHolder {

        private SetMultimap<String, Tuple<String, Boolean>> tenantsMM = null;

        public TenantHolder(SecurityDynamicConfiguration<RoleV7> roles, SecurityDynamicConfiguration<TenantV7> definedTenants) {
            final Set<Future<Tuple<String, Set<Tuple<String, Boolean>>>>> futures = new HashSet<>(roles.getCEntries().size());

            final ExecutorService execs = Executors.newFixedThreadPool(10);

            for (Entry<String, RoleV7> securityRole : roles.getCEntries().entrySet()) {

                if (securityRole.getValue() == null) {
                    continue;
                }

                Future<Tuple<String, Set<Tuple<String, Boolean>>>> future = execs.submit(
                    new Callable<Tuple<String, Set<Tuple<String, Boolean>>>>() {
                        @Override
                        public Tuple<String, Set<Tuple<String, Boolean>>> call() throws Exception {
                            final Set<Tuple<String, Boolean>> tuples = new HashSet<>();
                            final List<RoleV7.Tenant> tenants = securityRole.getValue().getTenant_permissions();
                            if (tenants != null) {

                                for (RoleV7.Tenant tenant : tenants) {

                                    // find Wildcarded tenant patterns
                                    List<String> matchingTenants = WildcardMatcher.from(tenant.getTenant_patterns())
                                        .getMatchAny(definedTenants.getCEntries().keySet(), Collectors.toList());
                                    for (String matchingTenant : matchingTenants) {
                                        tuples.add(
                                            new Tuple<String, Boolean>(
                                                matchingTenant,
                                                actionGroups.resolve(tenant.getAllowed_actions()).contains("kibana:saved_objects/*/write")
                                            )
                                        );
                                    }
                                    // find parameter substitution specified tenant
                                    Pattern parameterPattern = Pattern.compile("^\\$\\{attr");
                                    List<String> matchingParameterTenantList = tenant.getTenant_patterns()
                                        .stream()
                                        .filter(parameterPattern.asPredicate())
                                        .collect(Collectors.toList());
                                    for (String matchingParameterTenant : matchingParameterTenantList) {
                                        tuples.add(
                                            new Tuple<String, Boolean>(
                                                matchingParameterTenant,
                                                actionGroups.resolve(tenant.getAllowed_actions()).contains("kibana:saved_objects/*/write")
                                            )
                                        );
                                    }
                                }
                            }

                            return new Tuple<String, Set<Tuple<String, Boolean>>>(securityRole.getKey(), tuples);
                        }
                    }
                );

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
                final SetMultimap<String, Tuple<String, Boolean>> tenantsMM_ = SetMultimapBuilder.hashKeys(futures.size())
                    .hashSetValues(16)
                    .build();

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
                throw ExceptionsHelper.convertToOpenSearchException(e);
            }

        }

        public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {

            if (user == null || tenantsMM == null) {
                return Collections.emptyMap();
            }

            final Map<String, Boolean> result = new HashMap<>(roles.size());
            result.put(user.getName(), true);

            tenantsMM.entries()
                .stream()
                .filter(e -> roles.contains(e.getKey()))
                .filter(e -> !user.getName().equals(e.getValue().v1()))
                .forEach(e -> {

                    // replaceProperties for tenant name because
                    // at this point e.getValue().v1() can be in this form : "${attr.[internal|jwt|proxy|ldap].*}"
                    // let's substitute it with the eventual value of the user's attribute
                    final String tenant = UserAttributes.replaceProperties(e.getValue().v1(), user);
                    final boolean rw = e.getValue().v2();

                    if (rw || !result.containsKey(tenant)) { // RW outperforms RO

                        // We want to make sure that we add a tenant that exists
                        // Indeed, because we don't have control over what will be
                        // passed on as values of users' attributes, we have to make
                        // sure that we don't allow them to select tenants that do not exist.
                        if (ConfigModelV7.this.tenants.getCEntries().containsKey(tenant)) {
                            result.put(tenant, rw);
                        }
                    }
                });

            Set<String> _roles = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            _roles.addAll(roles);
            if (!result.containsKey("global_tenant") && (_roles.contains("kibana_user") || _roles.contains("all_access"))) {
                result.put("global_tenant", true);
            }

            return Collections.unmodifiableMap(result);
        }
    }

    private class RoleMappingHolder {

        private ListMultimap<String, String> users;
        private ListMultimap<List<WildcardMatcher>, String> abars;
        private ListMultimap<String, String> bars;
        private ListMultimap<String, String> hosts;
        private final String hostResolverMode;

        private List<WildcardMatcher> userMatchers;
        private List<WildcardMatcher> barMatchers;
        private List<WildcardMatcher> hostMatchers;

        private RoleMappingHolder(final SecurityDynamicConfiguration<RoleMappingsV7> rolemappings, final String hostResolverMode) {

            this.hostResolverMode = hostResolverMode;

            if (roles != null) {

                users = ArrayListMultimap.create();
                abars = ArrayListMultimap.create();
                bars = ArrayListMultimap.create();
                hosts = ArrayListMultimap.create();

                for (final Entry<String, RoleMappingsV7> roleMap : rolemappings.getCEntries().entrySet()) {
                    final String roleMapKey = roleMap.getKey();
                    final RoleMappingsV7 roleMapValue = roleMap.getValue();

                    for (String u : roleMapValue.getUsers()) {
                        users.put(u, roleMapKey);
                    }

                    final Set<String> abar = new HashSet<>(roleMapValue.getAnd_backend_roles());

                    if (!abar.isEmpty()) {
                        abars.put(WildcardMatcher.matchers(abar), roleMapKey);
                    }

                    for (String bar : roleMapValue.getBackend_roles()) {
                        bars.put(bar, roleMapKey);
                    }

                    for (String host : roleMapValue.getHosts()) {
                        hosts.put(host, roleMapKey);
                    }
                }

                userMatchers = WildcardMatcher.matchers(users.keySet());
                barMatchers = WildcardMatcher.matchers(bars.keySet());
                hostMatchers = WildcardMatcher.matchers(hosts.keySet());
            }
        }

        private Set<String> map(final User user, final TransportAddress caller) {

            if (user == null || users == null || abars == null || bars == null || hosts == null) {
                return Collections.emptySet();
            }

            final Set<String> securityRoles = new HashSet<>(user.getSecurityRoles());

            if (rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
                if (log.isDebugEnabled()) {
                    log.debug("Pass backendroles from {}", user);
                }
                securityRoles.addAll(user.getRoles());
            }

            if (((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {

                for (String p : WildcardMatcher.getAllMatchingPatterns(userMatchers, user.getName())) {
                    securityRoles.addAll(users.get(p));
                }
                for (String p : WildcardMatcher.getAllMatchingPatterns(barMatchers, user.getRoles())) {
                    securityRoles.addAll(bars.get(p));
                }

                for (List<WildcardMatcher> patterns : abars.keySet()) {
                    if (patterns.stream().allMatch(p -> p.matchAny(user.getRoles()))) {
                        securityRoles.addAll(abars.get(patterns));
                    }
                }

                if (caller != null) {
                    // IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();

                    for (String p : WildcardMatcher.getAllMatchingPatterns(hostMatchers, ipAddress)) {
                        securityRoles.addAll(hosts.get(p));
                    }

                    if (caller.address() != null
                        && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))) {
                        final String hostName = caller.address().getHostString();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hostMatchers, hostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }

                    if (caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")) {

                        final String resolvedHostName = caller.address().getHostName();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hostMatchers, resolvedHostName)) {
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
