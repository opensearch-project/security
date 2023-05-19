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

package org.opensearch.security.dlic.rest.api;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.StringContains.containsString;

public class MultiTenancyConfigApiTest extends AbstractRestApiUnitTest {

    private static final Header ADMIN_FULL_ACCESS_USER = encodeBasicHeader("admin_all_access", "admin_all_access");
    private static final Header USER_NO_REST_API_ACCESS = encodeBasicHeader("admin", "admin");

    private void verifyTenantUpdate(final Header... header) throws Exception {
        final HttpResponse getSettingResponse = rh.executeGetRequest("/_plugins/_security/api/tenancy/config", header);
        assertThat(getSettingResponse.getBody(), getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(
                getSettingResponse.getBody(),
                getSettingResponse.findValueInJson("default_tenant"),
                equalTo(ConfigConstants.TENANCY_GLOBAL_TENANT_DEFAULT_NAME)
        );

        HttpResponse getDashboardsinfoResponse = rh.executeGetRequest("/_plugins/_security/dashboardsinfo", header);
        assertThat(getDashboardsinfoResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(
                getDashboardsinfoResponse.getBody(),
                getDashboardsinfoResponse.findValueInJson("default_tenant"),
                equalTo(ConfigConstants.TENANCY_GLOBAL_TENANT_DEFAULT_NAME)
        );

        final HttpResponse setPrivateTenantAsDefaultResponse = rh.executePutRequest(
                "/_plugins/_security/api/tenancy/config",
                "{\"default_tenant\": \"Private\"}", header
        );
        assertThat(
                setPrivateTenantAsDefaultResponse.getBody(),
                setPrivateTenantAsDefaultResponse.getStatusCode(),
                equalTo(HttpStatus.SC_OK)
        );
        getDashboardsinfoResponse = rh.executeGetRequest("/_plugins/_security/dashboardsinfo", ADMIN_FULL_ACCESS_USER);
        assertThat(getDashboardsinfoResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getDashboardsinfoResponse.findValueInJson("default_tenant"), equalTo("Private"));
    }

    @Test
    public void testUpdateSuperAdmin() throws Exception {
        setupWithRestRoles();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        verifyTenantUpdate();
    }

    @Test
    public void testUpdateRestAPIAdmin() throws Exception {
        setupWithRestRoles();
        rh.sendAdminCertificate = false;
        verifyTenantUpdate(ADMIN_FULL_ACCESS_USER);
    }


    private void verifyTenantUpdateFailed(final Header... header) throws Exception {
        final HttpResponse disablePrivateTenantResponse = rh.executePutRequest(
                "/_plugins/_security/api/tenancy/config",
                "{\"private_tenant_enabled\":false}", header
        );
        assertThat(disablePrivateTenantResponse.getBody(), disablePrivateTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse setPrivateTenantAsDefaultFailResponse = rh.executePutRequest(
                "/_plugins/_security/api/tenancy/config",
                "{\"default_tenant\": \"Private\"}", header
        );
        assertThat(setPrivateTenantAsDefaultFailResponse.getBody(), setPrivateTenantAsDefaultFailResponse.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
        assertThat(
                setPrivateTenantAsDefaultFailResponse.getBody(),
                setPrivateTenantAsDefaultFailResponse.findValueInJson("error.reason"),
                containsString("Private tenant can not be disabled if it is the default tenant.")
        );

        final HttpResponse enablePrivateTenantResponse = rh.executePutRequest(
                "/_plugins/_security/api/tenancy/config",
                "{\"private_tenant_enabled\":true}",
                header
        );
        assertThat(enablePrivateTenantResponse.getBody(), enablePrivateTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse setPrivateTenantAsDefaultResponse = rh.executePutRequest(
                "/_plugins/_security/api/tenancy/config",
                "{\"default_tenant\": \"Private\"}",
                header
        );
        assertThat(setPrivateTenantAsDefaultResponse.getBody(), setPrivateTenantAsDefaultResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        final HttpResponse updatePrivateSettingResponse =
                rh.executePutRequest("/_plugins/_security/api/tenancy/config", "{\"private_tenant_enabled\":false}", header);
        assertThat(updatePrivateSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
        assertThat(updatePrivateSettingResponse.findValueInJson("error.reason"), containsString("Private tenant can not be disabled if it is the default tenant."));

        final HttpResponse getSettingResponseAfterUpdate = rh.executeGetRequest("/_plugins/_security/api/tenancy/config", header);
        assertThat(getSettingResponseAfterUpdate.getBody(), getSettingResponseAfterUpdate.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(
                getSettingResponseAfterUpdate.getBody(),
                getSettingResponseAfterUpdate.findValueInJson("default_tenant"),
                equalTo("Private")
        );

        final HttpResponse getDashboardsinfoResponse = rh.executeGetRequest("/_plugins/_security/dashboardsinfo", header);
        assertThat(
                getDashboardsinfoResponse.getBody(),
                getDashboardsinfoResponse.findValueInJson("default_tenant"),
                equalTo("Private")
        );

        final HttpResponse setRandomStringAsDefaultTenant = rh.executePutRequest(
                "/_plugins/_security/api/tenancy/config",
                "{\"default_tenant\": \"NonExistentTenant\"}",
                header
        );
        assertThat(setRandomStringAsDefaultTenant.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
        assertThat(setPrivateTenantAsDefaultFailResponse.getBody(),
                setRandomStringAsDefaultTenant.findValueInJson("error.reason"),
                containsString("Default tenant should be selected from one of the available tenants.")
        );
    }

    @Test
    public void testDefaultTenantUpdateFailedSuperAdmin() throws Exception {
        setupWithRestRoles();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
        verifyTenantUpdateFailed();
    }

    @Test
    public void testDefaultTenantUpdateFailedRestAPIAdmin() throws Exception {
        setupWithRestRoles();
        rh.sendAdminCertificate = false;
        verifyTenantUpdateFailed(ADMIN_FULL_ACCESS_USER);
    }

    @Test
    public void testForbiddenAccess() throws Exception {
        setupWithRestRoles();

        rh.sendAdminCertificate = false;
        HttpResponse getSettingResponse = rh.executeGetRequest("/_plugins/_security/api/tenancy/config", USER_NO_REST_API_ACCESS);
        assertThat(getSettingResponse.getBody(), getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        HttpResponse updateSettingResponse = rh.executePutRequest(
                "/_plugins/_security/api/tenancy/config",
                "{\"default_tenant\": \"Private\"}", USER_NO_REST_API_ACCESS
        );
        assertThat(getSettingResponse.getBody(), updateSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
    }


}
