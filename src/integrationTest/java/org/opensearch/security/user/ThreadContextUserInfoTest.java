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
package org.opensearch.security.user;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.privileges.DashboardsMultiTenancyConfiguration;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.TenantPrivileges;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.security.util.MockPrivilegeEvaluationContextBuilder;

import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests the tenant access value that ThreadContextUserInfo puts into the user info thread context transient.
 * Plugins such as reporting read this value to decide whether a user may write to the requested tenant.
 */
public class ThreadContextUserInfoTest {

    private TenantPrivileges tenantPrivileges;

    @Before
    public void setUp() throws Exception {
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("""
            tenant_reader:
               tenant_permissions:
               - tenant_patterns:
                 - global_tenant
                 - tenant_a
                 allowed_actions:
                 - "kibana:saved_objects/*/read"
            tenant_writer:
               tenant_permissions:
               - tenant_patterns:
                 - tenant_a
                 allowed_actions:
                 - "kibana:saved_objects/*/write"
            """, CType.ROLES);
        SecurityDynamicConfiguration<TenantV7> tenants = SecurityDynamicConfiguration.fromYaml("""
            global_tenant: {}
            tenant_a: {}
            """, CType.TENANTS);
        this.tenantPrivileges = new TenantPrivileges(roles, tenants, FlattenedActionGroups.EMPTY, false);
    }

    @Test
    public void privateTenant_writeAccessWithoutTenantPermissions() {
        assertEquals("WRITE", tenantAccess(multiTenancy(true), ctx("__user__")));
    }

    @Test
    public void privateTenant_noAccessWhenPrivateTenantDisabled() {
        assertEquals("NONE", tenantAccess(multiTenancy(false), ctx("__user__")));
    }

    @Test
    public void globalTenant_usesTenantPermissions() {
        assertEquals("READ", tenantAccess(multiTenancy(true), ctx(null, "tenant_reader")));
        assertEquals("NONE", tenantAccess(multiTenancy(true), ctx(null)));
    }

    @Test
    public void customTenant_usesTenantPermissions() {
        assertEquals("WRITE", tenantAccess(multiTenancy(true), ctx("tenant_a", "tenant_writer")));
        assertEquals("READ", tenantAccess(multiTenancy(true), ctx("tenant_a", "tenant_reader")));
        assertEquals("NONE", tenantAccess(multiTenancy(true), ctx("tenant_a")));
    }

    private String tenantAccess(DashboardsMultiTenancyConfiguration multiTenancyConfiguration, PrivilegesEvaluationContext context) {
        PrivilegesConfiguration privilegesConfiguration = mock(PrivilegesConfiguration.class);
        when(privilegesConfiguration.tenantPrivileges()).thenReturn(tenantPrivileges);
        when(privilegesConfiguration.multiTenancyConfiguration()).thenReturn(multiTenancyConfiguration);

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        new ThreadContextUserInfo(threadContext, privilegesConfiguration, null, Settings.EMPTY).setUserInfoInThreadContext(context);

        // Format: user name|backend roles|mapped roles|requested tenant|tenant access
        String userInfo = threadContext.getTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT);
        return userInfo.split("\\|", -1)[4];
    }

    private static DashboardsMultiTenancyConfiguration multiTenancy(boolean privateTenantEnabled) {
        ConfigV7.Kibana kibana = new ConfigV7.Kibana();
        kibana.multitenancy_enabled = true;
        kibana.private_tenant_enabled = privateTenantEnabled;
        return new DashboardsMultiTenancyConfiguration(kibana);
    }

    private static PrivilegesEvaluationContext ctx(String requestedTenant, String... roles) {
        return MockPrivilegeEvaluationContextBuilder.ctx().requestedTenant(requestedTenant).roles(roles).get();
    }
}
