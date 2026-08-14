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
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HostResolverMode;
import org.opensearch.security.user.User;

import static org.junit.Assert.assertEquals;

@RunWith(Suite.class)
@Suite.SuiteClasses({
    ConfigurableRoleMapperTest.ResolutionModeTest.class,
    ConfigurableRoleMapperTest.CompiledConfigurationTest.class,
    ConfigurableRoleMapperTest.CcsSkipSourceSecurityRolesTest.class, })
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

    public static class CcsSkipSourceSecurityRolesTest {

        @Test
        public void map_skipSourceSecurityRoles_excludesSourceRoles() throws Exception {
            User user = new User("ccs_user").withRoles("backend_role_1").withSecurityRoles(Arrays.asList("all_access"));

            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                read_only:
                  backend_roles:
                  - backend_role_1
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME,
                ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY
            );

            TransportAddress caller = new TransportAddress(InetAddress.getByAddress(new byte[] { 10, 0, 1, 50 }), 9300);

            // With skipSourceSecurityRoles=true: source cluster's all_access should NOT be included
            ImmutableSet<String> mappedRoles = compiled.map(user, caller, true);

            // Should only contain the role mapped by Domain B's own roles_mapping (read_only from backend_role_1)
            assertEquals(ImmutableSet.of("read_only"), mappedRoles);
        }

        @Test
        public void map_skipSourceSecurityRoles_false_includesSourceRoles() throws Exception {
            User user = new User("ccs_user").withRoles("backend_role_1").withSecurityRoles(Arrays.asList("all_access"));

            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                read_only:
                  backend_roles:
                  - backend_role_1
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME,
                ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY
            );

            TransportAddress caller = new TransportAddress(InetAddress.getByAddress(new byte[] { 10, 0, 1, 50 }), 9300);

            // With skipSourceSecurityRoles=false: source cluster's all_access SHOULD be included (current behavior)
            ImmutableSet<String> mappedRoles = compiled.map(user, caller, false);

            // Should contain both: source's all_access + Domain B's read_only
            assertEquals(ImmutableSet.of("all_access", "read_only"), mappedRoles);
        }

        @Test
        public void map_skipSourceSecurityRoles_noBackendRoles_emptyResult() throws Exception {
            User user = new User("ccs_user_no_backend").withSecurityRoles(Arrays.asList("all_access"));

            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                read_only:
                  backend_roles:
                  - some_other_role
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME,
                ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY
            );

            TransportAddress caller = new TransportAddress(InetAddress.getByAddress(new byte[] { 10, 0, 1, 50 }), 9300);

            // With skip=true and no matching backend_roles, user gets no roles on remote
            ImmutableSet<String> mappedRoles = compiled.map(user, caller, true);

            assertEquals(ImmutableSet.of(), mappedRoles);
        }

        @Test
        public void map_skipSourceSecurityRoles_withUsernameMapping() throws Exception {
            User user = new User("specific_user").withSecurityRoles(Arrays.asList("all_access"));

            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                limited_role:
                  users:
                  - specific_user
                """, CType.ROLESMAPPING);

            ConfigurableRoleMapper.CompiledConfiguration compiled = new ConfigurableRoleMapper.CompiledConfiguration(
                roleMapping,
                HostResolverMode.IP_HOSTNAME,
                ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY
            );

            TransportAddress caller = new TransportAddress(InetAddress.getByAddress(new byte[] { 10, 0, 1, 50 }), 9300);

            // With skip=true: source's all_access excluded, but username mapping still works
            ImmutableSet<String> mappedRoles = compiled.map(user, caller, true);

            assertEquals(ImmutableSet.of("limited_role"), mappedRoles);
        }

        @Test
        public void setCcsIgnoreSourceSecurityRoles_dynamicUpdate_changesMapBehavior() throws Exception {
            // Start with flag=false (default)
            Settings settingsOff = Settings.builder().put(ConfigConstants.SECURITY_CCS_IGNORE_SOURCE_SECURITY_ROLES, false).build();

            SecurityDynamicConfiguration<RoleMappingsV7> roleMapping = SecurityDynamicConfiguration.fromYaml("""
                read_only:
                  backend_roles:
                  - backend_role_1
                """, CType.ROLESMAPPING);

            ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST, Boolean.TRUE);

            ConfigurableRoleMapper mapper = new ConfigurableRoleMapper(
                null,
                ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY,
                threadContext,
                settingsOff
            );
            // Manually set active configuration since we passed null for configurationRepository
            mapper.setActiveConfiguration(
                new ConfigurableRoleMapper.CompiledConfiguration(
                    roleMapping,
                    HostResolverMode.IP_HOSTNAME,
                    ConfigurableRoleMapper.ResolutionMode.MAPPING_ONLY
                )
            );

            User user = new User("ccs_user").withRoles("backend_role_1").withSecurityRoles(Arrays.asList("all_access"));
            TransportAddress caller = new TransportAddress(InetAddress.getByAddress(new byte[] { 10, 0, 1, 50 }), 9300);

            // Flag=false: source roles included
            ImmutableSet<String> rolesBeforeUpdate = mapper.map(user, caller);
            assertEquals(ImmutableSet.of("all_access", "read_only"), rolesBeforeUpdate);

            // Simulate dynamic cluster settings update
            mapper.setCcsIgnoreSourceSecurityRoles(true);

            // Flag=true: source roles stripped
            ImmutableSet<String> rolesAfterUpdate = mapper.map(user, caller);
            assertEquals(ImmutableSet.of("read_only"), rolesAfterUpdate);
        }
    }

}
