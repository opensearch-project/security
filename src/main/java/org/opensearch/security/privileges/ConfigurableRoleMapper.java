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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HostResolverMode;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

/**
 * A RoleMapper implementation that automatically picks up changes from the role mapping configuration in the configuration index.
 */
public class ConfigurableRoleMapper implements RoleMapper {
    private final static Logger log = LogManager.getLogger(ConfigurableRoleMapper.class);

    private final AtomicReference<CompiledConfiguration> activeConfiguration = new AtomicReference<>();

    public ConfigurableRoleMapper(ConfigurationRepository configurationRepository, ResolutionMode resolutionMode) {
        if (configurationRepository != null) {
            configurationRepository.subscribeOnChange(configMap -> {
                HostResolverMode hostResolverMode = getHostResolverMode(configurationRepository.getConfiguration(CType.CONFIG));
                SecurityDynamicConfiguration<RoleMappingsV7> rawRoleMappingConfiguration = configurationRepository.getConfiguration(
                    CType.ROLESMAPPING
                );
                if (rawRoleMappingConfiguration == null) {
                    rawRoleMappingConfiguration = SecurityDynamicConfiguration.empty(CType.ROLESMAPPING);
                }

                this.activeConfiguration.set(new CompiledConfiguration(rawRoleMappingConfiguration, hostResolverMode, resolutionMode));
            });
        }
    }

    public ConfigurableRoleMapper(ConfigurationRepository configurationRepository, Settings settings) {
        this(configurationRepository, ResolutionMode.fromSettings(settings));
    }

    @Override
    public ImmutableSet<String> map(User user, TransportAddress caller) {
        CompiledConfiguration activeConfiguration = this.activeConfiguration.get();

        if (activeConfiguration != null) {
            return activeConfiguration.map(user, caller);
        } else {
            return ImmutableSet.of();
        }
    }

    /**
     * Determines which roles are used in the final set of effective roles returned by the map() method.
     *
     * The setting is sourced from the plugins.secutiry.roles_mapping_resolution setting.
     */
    enum ResolutionMode {
        /**
         * Include only the target roles from the role mapping configuration.
         */
        MAPPING_ONLY,

        /**
         * Include only the backend roles. This effectively disables the role mapping process.
         */
        BACKENDROLES_ONLY,

        /**
         * Include the union of the target roles and the source backend roles.
         */
        BOTH;

        static ResolutionMode fromSettings(Settings settings) {

            try {
                return ResolutionMode.valueOf(
                    settings.get(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, ResolutionMode.MAPPING_ONLY.toString()).toUpperCase()
                );
            } catch (Exception e) {
                log.error("Cannot apply roles mapping resolution", e);
                return ResolutionMode.MAPPING_ONLY;
            }
        }
    }

    static HostResolverMode getHostResolverMode(SecurityDynamicConfiguration<ConfigV7> configConfig) {
        final HostResolverMode defaultValue = HostResolverMode.IP_HOSTNAME;

        if (configConfig == null) {
            return defaultValue;
        }

        ConfigV7 config = configConfig.getCEntry(CType.CONFIG.name());
        if (config == null || config.dynamic == null) {
            return defaultValue;
        }
        return HostResolverMode.fromConfig(config.dynamic.hosts_resolver_mode);
    }

    /**
     * Moved from https://github.com/opensearch-project/security/blob/d29095f26dba1a26308c69b608dc926bd40c0f52/src/main/java/org/opensearch/security/securityconf/ConfigModelV7.java
     */
    static class CompiledConfiguration implements RoleMapper {

        private final ResolutionMode resolutionMode;
        private final HostResolverMode hostResolverMode;

        private ListMultimap<String, String> users;
        private ListMultimap<List<WildcardMatcher>, String> abars;
        private ListMultimap<String, String> bars;
        private ListMultimap<String, String> hosts;

        private List<WildcardMatcher> userMatchers;
        private List<WildcardMatcher> barMatchers;
        private List<WildcardMatcher> hostMatchers;

        CompiledConfiguration(
            SecurityDynamicConfiguration<RoleMappingsV7> rolemappings,
            HostResolverMode hostResolverMode,
            ResolutionMode resolutionMode
        ) {

            this.hostResolverMode = hostResolverMode;
            this.resolutionMode = resolutionMode;

            users = ArrayListMultimap.create();
            abars = ArrayListMultimap.create();
            bars = ArrayListMultimap.create();
            hosts = ArrayListMultimap.create();

            for (final Map.Entry<String, RoleMappingsV7> roleMap : rolemappings.getCEntries().entrySet()) {
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

        @Override
        public ImmutableSet<String> map(final User user, final TransportAddress caller) {

            if (user == null) {
                return ImmutableSet.of();
            }

            ImmutableSet.Builder<String> result = ImmutableSet.builderWithExpectedSize(
                user.getSecurityRoles().size() + user.getRoles().size()
            );

            result.addAll(user.getSecurityRoles());

            if (resolutionMode == ResolutionMode.BOTH || resolutionMode == ResolutionMode.BACKENDROLES_ONLY) {
                result.addAll(user.getRoles());
            }

            if (((resolutionMode == ResolutionMode.BOTH || resolutionMode == ResolutionMode.MAPPING_ONLY))) {

                for (String p : WildcardMatcher.getAllMatchingPatterns(userMatchers, user.getName())) {
                    result.addAll(users.get(p));
                }
                for (String p : WildcardMatcher.getAllMatchingPatterns(barMatchers, user.getRoles())) {
                    result.addAll(bars.get(p));
                }

                for (List<WildcardMatcher> patterns : abars.keySet()) {
                    if (patterns.stream().allMatch(p -> p.matchAny(user.getRoles()))) {
                        result.addAll(abars.get(patterns));
                    }
                }

                if (caller != null) {
                    // IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();

                    for (String p : WildcardMatcher.getAllMatchingPatterns(hostMatchers, ipAddress)) {
                        result.addAll(hosts.get(p));
                    }

                    if (caller.address() != null
                        && (hostResolverMode == HostResolverMode.IP_HOSTNAME || hostResolverMode == HostResolverMode.IP_HOSTNAME_LOOKUP)) {
                        final String hostName = caller.address().getHostString();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hostMatchers, hostName)) {
                            result.addAll(hosts.get(p));
                        }
                    }

                    if (caller.address() != null && hostResolverMode == HostResolverMode.IP_HOSTNAME_LOOKUP) {

                        final String resolvedHostName = caller.address().getHostName();

                        for (String p : WildcardMatcher.getAllMatchingPatterns(hostMatchers, resolvedHostName)) {
                            result.addAll(hosts.get(p));
                        }
                    }
                }
            }

            return result.build();
        }
    }

}
