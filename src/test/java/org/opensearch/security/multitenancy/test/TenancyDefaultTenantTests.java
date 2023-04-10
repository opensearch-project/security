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

package org.opensearch.security.multitenancy.test;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.StringContains.containsString;

public class TenancyDefaultTenantTests extends SingleClusterTest {
    private final Header asAdminUser = encodeBasicHeader("admin", "admin");
    private final Header asUser = encodeBasicHeader("kirk", "kirk");

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }

    @Test
    public void testDefaultTenantUpdate() throws Exception {
        setup();

        final HttpResponse getSettingResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/api/tenancy/config", asAdminUser);
        assertThat(getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getSettingResponse.findValueInJson("default_tenant"), equalTo(ConfigConstants.TENANCY_GLOBAL_TENANT_DEFAULT_NAME));

        HttpResponse getDashboardsinfoResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/dashboardsinfo", asAdminUser);
        assertThat(getDashboardsinfoResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getDashboardsinfoResponse.findValueInJson("default_tenant"), equalTo(ConfigConstants.TENANCY_GLOBAL_TENANT_DEFAULT_NAME));

        final HttpResponse setPrivateTenantAsDefaultResponse = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"default_tenant\": \"Private\"}", asAdminUser);
        assertThat(setPrivateTenantAsDefaultResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        getDashboardsinfoResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/dashboardsinfo", asAdminUser);
        assertThat(getDashboardsinfoResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getDashboardsinfoResponse.findValueInJson("default_tenant"), equalTo(ConfigConstants.TENANCY_PRIVATE_TENANT_NAME));
    }

    @Test
    public void testDefaultTenant_UpdateFailed() throws Exception {
        setup();

        final HttpResponse disablePrivateTenantResponse = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"private_tenant_enabled\":false}", asAdminUser);
        assertThat(disablePrivateTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));


        final HttpResponse setPrivateTenantAsDefaultFailResponse = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"default_tenant\": \"Private\"}", asAdminUser);
        assertThat(setPrivateTenantAsDefaultFailResponse.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
        assertThat(setPrivateTenantAsDefaultFailResponse.findValueInJson("error.reason"), containsString("Private tenant can not be disabled if it is the default tenant."));

        final HttpResponse enablePrivateTenantResponse = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"private_tenant_enabled\":true}", asAdminUser);
        assertThat(enablePrivateTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse setPrivateTenantAsDefaultResponse = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"default_tenant\": \"Private\"}", asAdminUser);
        assertThat(setPrivateTenantAsDefaultResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse getSettingResponseAfterUpdate = nonSslRestHelper().executeGetRequest("/_plugins/_security/api/tenancy/config", asAdminUser);
        assertThat(getSettingResponseAfterUpdate.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getSettingResponseAfterUpdate.findValueInJson("default_tenant"), equalTo(ConfigConstants.TENANCY_PRIVATE_TENANT_NAME));

        HttpResponse getDashboardsinfoResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/dashboardsinfo", asAdminUser);
        assertThat(getDashboardsinfoResponse.findValueInJson("default_tenant"),equalTo(ConfigConstants.TENANCY_PRIVATE_TENANT_NAME));

        final HttpResponse setRandomStringAsDefaultTenant = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"default_tenant\": \"NonExistentTenant\"}", asAdminUser);
        assertThat(setRandomStringAsDefaultTenant.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
        assertThat(setRandomStringAsDefaultTenant.findValueInJson("error.reason"), containsString("Default tenant should be selected from one of the available tenants."));

    }
    @Test
    public void testForbiddenAccess() throws Exception {
        setup();

        final HttpResponse getSettingResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/api/tenancy/config", asUser);
        assertThat(getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        assertThat(getSettingResponse.findValueInJson("error.reason"), containsString("no permissions for [cluster:feature/tenancy/config/read]"));

        final HttpResponse updateSettingResponse = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"default_tenant\": \"Private\"}", asUser);
        assertThat(updateSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        assertThat(updateSettingResponse.findValueInJson("error.reason"), containsString("no permissions for [cluster:feature/tenancy/config/update]"));
    }
}
