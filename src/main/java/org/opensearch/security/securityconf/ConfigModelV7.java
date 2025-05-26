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
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HostResolverMode;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

public class ConfigModelV7 extends ConfigModel {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private ConfigConstants.RolesMappingResolution rolesMappingResolution;
    private RoleMappingHolder roleMappingHolder;
    private SecurityDynamicConfiguration<RoleV7> roles;

    public ConfigModelV7(
        SecurityDynamicConfiguration<RoleV7> roles,
        SecurityDynamicConfiguration<RoleMappingsV7> rolemappings,
        DynamicConfigModel dcm,
        Settings opensearchSettings
    ) {

        this.roles = roles;

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

        roleMappingHolder = new RoleMappingHolder(rolemappings, dcm.getHostsResolverMode());
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
                        && (hostResolverMode.equalsIgnoreCase(HostResolverMode.IP_HOSTNAME.getValue())
                            || hostResolverMode.equalsIgnoreCase(HostResolverMode.IP_HOSTNAME_LOOKUP.getValue()))) {
                        final String hostName = caller.address().getHostString();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hostMatchers, hostName)) {
                            securityRoles.addAll(hosts.get(p));
                        }
                    }

                    if (caller.address() != null && hostResolverMode.equalsIgnoreCase(HostResolverMode.IP_HOSTNAME_LOOKUP.getValue())) {

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

    public Set<String> mapSecurityRoles(User user, TransportAddress caller) {
        return roleMappingHolder.map(user, caller);
    }
}
