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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.security.user.User;

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
            this.subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY);
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

            TenantPrivileges subject = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY);
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
                FlattenedActionGroups.EMPTY
            );
            assertEquals(Set.of("tenant_a1", "tenant_a2", "tenant_b1", "tenant_b2"), subject.allTenantNames());
        }

        @Test
        public void allAccess() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
                IOUtils.toString(DynamicConfigFactory.class.getResourceAsStream("/static_config/static_roles.yml"), StandardCharsets.UTF_8),
                CType.ROLES
            );
            SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml(
                IOUtils.toString(
                    DynamicConfigFactory.class.getResourceAsStream("/static_config/static_tenants.yml"),
                    StandardCharsets.UTF_8
                ),
                CType.TENANTS
            );
            SecurityDynamicConfiguration<ActionGroupsV7> actionGroups = SecurityDynamicConfiguration.fromYaml(
                IOUtils.toString(
                    DynamicConfigFactory.class.getResourceAsStream("/static_config/static_action_groups.yml"),
                    StandardCharsets.UTF_8
                ),
                CType.ACTIONGROUPS
            );

            TenantPrivileges subject = new TenantPrivileges(roles, tenants, new FlattenedActionGroups(actionGroups));

            assertTrue(subject.hasTenantPrivilege(ctx("all_access"), "global_tenant", TenantPrivileges.ActionType.WRITE));
        }
    }

    static PrivilegesEvaluationContext ctx(String... roles) {
        User user = new User("test_user");
        user.addAttributes(ImmutableMap.of("attrs.dept_no", "a1"));
        return new PrivilegesEvaluationContext(
            user,
            ImmutableSet.copyOf(roles),
            null,
            null,
            null,
            null,
            new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)),
            null
        );
    }

    static PrivilegesEvaluationContext ctxWithDifferentUserAttr(String... roles) {
        User user = new User("test_user");
        user.addAttributes(ImmutableMap.of("attrs.dept_no", "a10"));
        return new PrivilegesEvaluationContext(
            user,
            ImmutableSet.copyOf(roles),
            null,
            null,
            null,
            null,
            new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)),
            null
        );
    }
}
