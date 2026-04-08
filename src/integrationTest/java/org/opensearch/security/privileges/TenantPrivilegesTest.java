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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;

import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.security.util.MockPrivilegeEvaluationContextBuilder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the class TenantPrivileges
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ TenantPrivilegesTest.ParameterizedByRoleConfiguration.class, TenantPrivilegesTest.Misc.class })
public class TenantPrivilegesTest {

    /**
     * A parameterized test class for the method TenantPrivileges.hasTenantPrivileges(). Tests the return value based
     * on different kinds of roles.yml configurations.
     */
    @RunWith(Parameterized.class)
    public static class ParameterizedByRoleConfiguration {
        TenantPrivilegeSpec spec;
        TenantPrivileges subject;

        @Test
        public void positive_read() throws Exception {
            boolean result = subject.hasTenantPrivilege(ctx("test_role"), "tenant_a1", TenantPrivileges.ActionType.READ);

            if (spec.isEmpty() || spec.isInvalid()) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void write() throws Exception {
            boolean result = subject.hasTenantPrivilege(ctx("test_role"), "tenant_a1", TenantPrivileges.ActionType.WRITE);
            if (spec.isWrite() && !spec.isInvalid()) {
                assertTrue(result);
            } else {
                assertFalse(result);
            }
        }

        @Test
        public void negative_wrongRole() throws Exception {
            assertFalse(subject.hasTenantPrivilege(ctx("other_role"), "tenant_a1", TenantPrivileges.ActionType.READ));
        }

        @Test
        public void negative_wrongTenant() throws Exception {
            assertFalse(subject.hasTenantPrivilege(ctx("test_role"), "tenant_a3", TenantPrivileges.ActionType.READ));
        }

        @Test
        public void wrongTenantByUserAttr() throws Exception {
            boolean result = subject.hasTenantPrivilege(
                ctxWithDifferentUserAttr("test_role"),
                "tenant_a1",
                TenantPrivileges.ActionType.READ
            );

            if (spec.tenantsContainUserAttr() || spec.isEmpty() || spec.isInvalid()) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Parameterized.Parameters(name = "{0}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            result.add(
                new Object[] {
                    new TenantPrivilegeSpec("constant tenant; write").tenantPatterns("tenant_a1")
                        .allowedActions("kibana:saved_objects/*/write") }
            );
            result.add(
                new Object[] {
                    new TenantPrivilegeSpec("constant tenant; read").tenantPatterns("tenant_a1")
                        .allowedActions("kibana:saved_objects/*/read") }
            );
            result.add(
                new Object[] {
                    new TenantPrivilegeSpec("tenant pattern; write").tenantPatterns("tenant_a*")
                        .allowedActions("kibana:saved_objects/*/write") }
            );
            result.add(
                new Object[] {
                    new TenantPrivilegeSpec("tenant pattern; read").tenantPatterns("tenant_a*")
                        .allowedActions("kibana:saved_objects/*/read") }
            );
            result.add(
                new Object[] {
                    new TenantPrivilegeSpec("tenant w/ user attribute; write").tenantPatterns("tenant_${attrs.dept_no}")
                        .allowedActions("kibana:saved_objects/*/write") }
            );
            result.add(
                new Object[] {
                    new TenantPrivilegeSpec("tenant w/ user attribute; read").tenantPatterns("tenant_${attrs.dept_no}")
                        .allowedActions("kibana:saved_objects/*/read") }
            );
            result.add(new Object[] { new TenantPrivilegeSpec("no tenant config") });
            result.add(
                new Object[] {
                    new TenantPrivilegeSpec("invalid tenant pattern").tenantPatterns("/.*|{/")
                        .allowedActions("kibana:saved_objects/*/write") }
            );

            return result;
        }

        public ParameterizedByRoleConfiguration(TenantPrivilegeSpec spec) throws Exception {
            this.spec = spec;
            SecurityDynamicConfiguration<RoleV7> roles = spec.toRolesConfig();
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml("""
                tenant_a1: {}
                tenant_a2: {}
                tenant_b1: {}
                tenant_b2: {}
                """, CType.TENANTS);
            this.subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY, false);
        }

        public static class TenantPrivilegeSpec {
            String description;
            List<String> tenantPatterns = new ArrayList<>();
            List<String> allowedActions = new ArrayList<>();

            TenantPrivilegeSpec(String description) {
                this.description = description;
            }

            TenantPrivilegeSpec tenantPatterns(String... tenantPatterns) {
                this.tenantPatterns = Arrays.asList(tenantPatterns);
                return this;
            }

            TenantPrivilegeSpec allowedActions(String... allowedActions) {
                this.allowedActions = Arrays.asList(allowedActions);
                return this;
            }

            boolean tenantsContainUserAttr() {
                return this.tenantPatterns.stream().anyMatch(t -> t.contains("${"));
            }

            boolean isWrite() {
                return this.allowedActions.contains("kibana:saved_objects/*/write");
            }

            boolean isEmpty() {
                return this.allowedActions.isEmpty() && this.tenantPatterns.isEmpty();
            }

            boolean isInvalid() {
                return description.contains("invalid");
            }

            SecurityDynamicConfiguration<RoleV7> toRolesConfig() {
                try {
                    if (!isEmpty()) {
                        return SecurityDynamicConfiguration.fromMap(
                            ImmutableMap.of(
                                "test_role",
                                ImmutableMap.of(
                                    "tenant_permissions",
                                    List.of(ImmutableMap.of("tenant_patterns", this.tenantPatterns, "allowed_actions", this.allowedActions))
                                )
                            ),
                            CType.ROLES
                        );
                    } else {
                        return SecurityDynamicConfiguration.fromMap(
                            ImmutableMap.of("test_role", ImmutableMap.of("description", "empty role")),
                            CType.ROLES
                        );
                    }
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public String toString() {
                return description;
            }
        }

    }

    public static class Misc {
        @Test
        public void tenantMap() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("""
                test_role:
                   tenant_permissions:
                   - tenant_patterns:
                     - tenant_a*
                     allowed_actions:
                     - "kibana:saved_objects/*/read"
                   - tenant_patterns:
                     - tenant_a1
                     allowed_actions:
                     - "kibana:saved_objects/*/write"
                """, CType.ROLES);
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml("""
                tenant_a1: {}
                tenant_a2: {}
                tenant_b1: {}
                tenant_b2: {}
                """, CType.TENANTS);

            TenantPrivileges subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY, false);
            assertEquals(Map.of("test_user", true, "tenant_a1", true, "tenant_a2", false), subject.tenantMap(ctx("test_role")));
        }

        @Test
        public void allTenantNames() throws Exception {
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml("""
                tenant_a1: {}
                tenant_a2: {}
                tenant_b1: {}
                tenant_b2: {}
                """, CType.TENANTS);

            TenantPrivileges subject = new TenantPrivileges(
                SecurityDynamicConfiguration.empty(CType.ROLES),
                tenants,
                FlattenedActionGroups.EMPTY,
                false
            );
            assertEquals(Set.of("tenant_a1", "tenant_a2", "tenant_b1", "tenant_b2"), subject.allTenantNames());
        }

        @Test
        public void allAccess() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
                testResource("/static_config/static_roles.yml"),
                CType.ROLES
            );
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml(
                testResource("/static_config/static_tenants.yml"),
                CType.TENANTS
            );
            SecurityDynamicConfiguration<ActionGroupsV7> actionGroups = SecurityDynamicConfiguration.fromYaml(
                testResource("/static_config/static_action_groups.yml"),
                CType.ACTIONGROUPS
            );

            TenantPrivileges subject = new TenantPrivileges(roles, tenants, new FlattenedActionGroups(actionGroups), false);
            assertTrue(subject.hasTenantPrivilege(ctx("all_access"), "global_tenant", TenantPrivileges.ActionType.WRITE));
        }

        @Test
        public void invalidDynamicTenantPattern() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("""
                test_role:
                   tenant_permissions:
                   - tenant_patterns:
                     - "/${user.roles}a{/"
                     allowed_actions:
                     - "kibana:saved_objects/*/read"
                """, CType.ROLES);
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml("""
                tenant_a1: {}
                """, CType.TENANTS);

            TenantPrivileges subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY, false);
            assertFalse(subject.hasTenantPrivilege(ctx("test_role"), "tenant_a1", TenantPrivileges.ActionType.READ));
        }

        /**
         * This tests legacy behavior which should be removed during the next major release;
         * see https://github.com/opensearch-project/security/issues/5356
         */
        @Test
        public void implicitGlobalTenantAccessGrantedByKibanaUserRole_granted() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("""
                test_role: {}
                """, CType.ROLES);
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml("""
                tenant_a1: {}
                global_tenant: {}
                """, CType.TENANTS);

            TenantPrivileges subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY, true);

            assertTrue(subject.hasTenantPrivilege(ctx("kibana_user"), "global_tenant", TenantPrivileges.ActionType.WRITE));
            assertTrue(subject.hasTenantPrivilege(ctx("kibana_user"), "global_tenant", TenantPrivileges.ActionType.READ));

            assertFalse(subject.hasTenantPrivilege(ctx("not_kibana_user"), "global_tenant", TenantPrivileges.ActionType.WRITE));
            assertFalse(subject.hasTenantPrivilege(ctx("not_kibana_user"), "global_tenant", TenantPrivileges.ActionType.READ));

            roles = SecurityDynamicConfiguration.fromYaml("""
                test_role:
                   tenant_permissions:
                   - tenant_patterns:
                     - "*"
                     allowed_actions:
                     - "kibana:saved_objects/*/read"
                """, CType.ROLES);

            subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY, true);

            assertTrue(subject.hasTenantPrivilege(ctx("kibana_user"), "global_tenant", TenantPrivileges.ActionType.WRITE));
            assertTrue(subject.hasTenantPrivilege(ctx("kibana_user"), "global_tenant", TenantPrivileges.ActionType.READ));

        }

        /**
         * This tests legacy behavior which should be removed during the next major release;
         * see https://github.com/opensearch-project/security/issues/5356
         */
        @Test
        public void implicitGlobalTenantAccessGrantedByKibanaUserRole_notGranted() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("""
                test_role:
                   tenant_permissions:
                   - tenant_patterns:
                     - "*"
                     allowed_actions:
                     - "kibana:saved_objects/*/read"
                """, CType.ROLES);
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml("""
                tenant_a1: {}
                global_tenant: {}
                """, CType.TENANTS);

            TenantPrivileges subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY, false);

            assertFalse(subject.hasTenantPrivilege(ctx("test_role", "kibana_user"), "global_tenant", TenantPrivileges.ActionType.WRITE));
            assertTrue(subject.hasTenantPrivilege(ctx("test_role", "kibana_user"), "global_tenant", TenantPrivileges.ActionType.READ));
        }

    }

    static PrivilegesEvaluationContext ctx(String... roles) {
        return MockPrivilegeEvaluationContextBuilder.ctx().roles(roles).attr("attrs.dept_no", "a1").get();
    }

    static PrivilegesEvaluationContext ctxWithDifferentUserAttr(String... roles) {
        return MockPrivilegeEvaluationContextBuilder.ctx().roles(roles).attr("attrs.dept_no", "a10").get();
    }

    static String testResource(String fileName) throws IOException {
        InputStream in = DynamicConfigFactory.class.getResourceAsStream(fileName);

        if (in == null) {
            throw new FileNotFoundException("could not find " + fileName);
        }

        return IOUtils.toString(in, StandardCharsets.UTF_8);
    }
}
