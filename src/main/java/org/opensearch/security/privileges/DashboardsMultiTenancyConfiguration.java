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

import org.opensearch.security.securityconf.impl.v7.ConfigV7;

/**
 * Provides access to the current configuration related to Dashboards multi-tenancy.
 * <p>
 * This replaces methods from PrivilegesEvaluator: https://github.com/opensearch-project/security/blob/062ea716d10240cc50d01735f457523a61393a59/src/main/java/org/opensearch/security/privileges/PrivilegesEvaluator.java#L690-L719
 */
public class DashboardsMultiTenancyConfiguration {
    public static final DashboardsMultiTenancyConfiguration DEFAULT = new DashboardsMultiTenancyConfiguration(new ConfigV7.Kibana());

    private final boolean multitenancyEnabled;
    private final boolean privateTenantEnabled;
    private final String defaultTenant;
    private final String index;
    private final String serverUsername;
    private final String role;

    public DashboardsMultiTenancyConfiguration(ConfigV7.Kibana dashboardsConfig) {
        this.multitenancyEnabled = dashboardsConfig.multitenancy_enabled;
        this.privateTenantEnabled = dashboardsConfig.private_tenant_enabled;
        this.defaultTenant = dashboardsConfig.default_tenant;
        this.index = dashboardsConfig.index;
        this.serverUsername = dashboardsConfig.server_username;
        this.role = dashboardsConfig.opendistro_role;
    }

    public DashboardsMultiTenancyConfiguration(ConfigV7 generalConfig) {
        this(dashboardsConfig(generalConfig));
    }

    public boolean multitenancyEnabled() {
        return multitenancyEnabled;
    }

    public boolean privateTenantEnabled() {
        return privateTenantEnabled;
    }

    public String dashboardsDefaultTenant() {
        return defaultTenant;
    }

    public String dashboardsIndex() {
        return index;
    }

    public String dashboardsServerUsername() {
        return serverUsername;
    }

    public String dashboardsOpenSearchRole() {
        return role;
    }

    private static ConfigV7.Kibana dashboardsConfig(ConfigV7 generalConfig) {
        if (generalConfig != null && generalConfig.dynamic != null && generalConfig.dynamic.kibana != null) {
            return generalConfig.dynamic.kibana;
        } else {
            // Fallback to defaults
            return new ConfigV7.Kibana();
        }
    }

}
