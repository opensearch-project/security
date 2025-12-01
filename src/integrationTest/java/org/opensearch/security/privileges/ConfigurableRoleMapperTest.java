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

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HostResolverMode;
import org.opensearch.security.user.User;

import static org.junit.Assert.assertEquals;

@RunWith(Suite.class)
@Suite.SuiteClasses({ ConfigurableRoleMapperTest.ResolutionModeTest.class, ConfigurableRoleMapperTest.CompiledConfigurationTest.class, })
public class ConfigurableRoleMapperTest {

    public static class ResolutionModeTest {
        @Test
        public void fromSettings_valid() {
            Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, "both").build();

            assertEquals(ConfigurableRoleMapper.ResolutionMode.BOTH, ConfigurableRoleMapper.ResolutionMode.fromSettings(settings));
        }

        @Test
        public void fromSettings_invalid() {
            Settings settings = Settings.builder().put(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, "totally_invalid_value").build();

            // invalid -> fallback to MAPPING_ONLY
            assertEquals(ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY, ConfigurableRoleMapper.ResolutionMode.fromSettings(settings));
        }
    }

    @RunWith(Parameterized.class)
    public static class CompiledConfigurationTest {

        final static User USER_WITH_NO_ROLES = new User("user_no_roles");
        final static User USER_WITH_BACKEND_ROLES = new User("user_with_backend_roles").withRoles("backend_role_1", "backend_role_2");
        final static User USER_WITH_SECURITY_ROLES = new User("user_with_security_roles").withSecurityRoles(
            Arrays.asList("effective_role_1", "effective_role_2")
        );
        final static User USER_WITH_BOTH = new User("user_with_both").withRoles("backend_role_1", "backend_role_2")
            .withSecurityRoles(Arrays.asList("effective_role_1", "effective_role_2"));

        final ConfigurableRoleMapper.ResolutionMode resolutionMode;
        final User user;
        final TransportAddress transportAddress;

        @Test
        public void map_simple() throws Exception {
            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                backend_to_effective:
                  backend_roles:
                  - backend_role_1
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME,
                resolutionMode
            );

            ImmutableSet<String> mappedRoles = compiled.map(user, transportAddress);
            Set<String> expectedRoles = new HashSet<>(user.getSecurityRoles());

            if (resolutionMode == ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY
                || resolutionMode == ConfigurableRoleMapper.ResolutionMode.BOTH) {
                if (user.getRoles().contains("backend_role_1")) {
                    expectedRoles.add("backend_to_effective");
                }
            }

            if (resolutionMode == ConfigurableRoleMapper.ResolutionMode.BACKENDROLES_ONLY
                || resolutionMode == ConfigurableRoleMapper.ResolutionMode.BOTH) {
                expectedRoles.addAll(user.getRoles());
            }

            assertEquals(expectedRoles, mappedRoles);

        }

        @Test
        public void map_username() throws Exception {
            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                user_to_effective:
                  users:
                  - user_no_roles
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME,
                resolutionMode
            );

            ImmutableSet<String> mappedRoles = compiled.map(user, transportAddress);
            Set<String> expectedRoles = new HashSet<>(user.getSecurityRoles());

            if (user == USER_WITH_NO_ROLES && resolutionMode != ConfigurableRoleMapper.ResolutionMode.BACKENDROLES_ONLY) {
                expectedRoles.add("user_to_effective");
            }

            if (resolutionMode == ConfigurableRoleMapper.ResolutionMode.BACKENDROLES_ONLY
                || resolutionMode == ConfigurableRoleMapper.ResolutionMode.BOTH) {
                expectedRoles.addAll(user.getRoles());
            }

            assertEquals(expectedRoles, mappedRoles);
        }

        @Test
        public void map_host() throws Exception {
            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                host_to_effective:
                  hosts:
                  - "127.0.0.1"
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME_LOOKUP,
                resolutionMode
            );

            ImmutableSet<String> mappedRoles = compiled.map(user, transportAddress);
            Set<String> expectedRoles = new HashSet<>(user.getSecurityRoles());

            if (resolutionMode != ConfigurableRoleMapper.ResolutionMode.BACKENDROLES_ONLY) {
                expectedRoles.add("host_to_effective");
            }

            if (resolutionMode == ConfigurableRoleMapper.ResolutionMode.BACKENDROLES_ONLY
                || resolutionMode == ConfigurableRoleMapper.ResolutionMode.BOTH) {
                expectedRoles.addAll(user.getRoles());
            }

            assertEquals(expectedRoles, mappedRoles);
        }

        @Test
        public void map_and() throws Exception {
            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                backend_to_effective:
                  and_backend_roles:
                  - backend_role_1
                  - backend_role_2
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME,
                resolutionMode
            );

            ImmutableSet<String> mappedRoles = compiled.map(user, transportAddress);
            Set<String> expectedRoles = new HashSet<>(user.getSecurityRoles());

            if (resolutionMode == ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY
                || resolutionMode == ConfigurableRoleMapper.ResolutionMode.BOTH) {
                if (user.getRoles().contains("backend_role_1") && user.getRoles().contains("backend_role_2")) {
                    expectedRoles.add("backend_to_effective");
                }
            }

            if (resolutionMode == ConfigurableRoleMapper.ResolutionMode.BACKENDROLES_ONLY
                || resolutionMode == ConfigurableRoleMapper.ResolutionMode.BOTH) {
                expectedRoles.addAll(user.getRoles());
            }

            assertEquals(expectedRoles, mappedRoles);

        }

        public CompiledConfigurationTest(
            ConfigurableRoleMapper.ResolutionMode resolutionMode,
            User user,
            TransportAddress transportAddress
        ) {
            this.resolutionMode = resolutionMode;
            this.user = user;
            this.transportAddress = transportAddress;
        }

        @Parameterized.Parameters(name = "{0}, {1}")
        public static Collection<Object[]> params() throws Exception {
            List<Object[]> result = new ArrayList<>();

            for (ConfigurableRoleMapper.ResolutionMode mode : ConfigurableRoleMapper.ResolutionMode.values()) {
                for (User user : Arrays.asList(USER_WITH_NO_ROLES, USER_WITH_BACKEND_ROLES, USER_WITH_SECURITY_ROLES, USER_WITH_BOTH)) {
                    result.add(
                        new Object[] { mode, user, new TransportAddress(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }), 9300) }
                    );

                }
            }

            return result;
        }

    }

}
