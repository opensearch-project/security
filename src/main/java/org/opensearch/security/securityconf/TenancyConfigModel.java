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

package org.opensearch.security.securityconf;
import org.opensearch.security.securityconf.impl.v7.TenancyConfigV7;

public class TenancyConfigModel {
    private final TenancyConfigV7 tenancyConfig;

    public TenancyConfigModel(TenancyConfigV7 tenancyConfig) {
        this.tenancyConfig = tenancyConfig;
    }

    public boolean isDashboardsMultitenancyEnabled() { return this.tenancyConfig.multitenancy_enabled; };
    public boolean isDashboardsPrivateTenantEnabled() { return this.tenancyConfig.private_tenant_enabled; };
    public String dashboardsDefaultTenant() { return this.tenancyConfig.default_tenant; };
}

