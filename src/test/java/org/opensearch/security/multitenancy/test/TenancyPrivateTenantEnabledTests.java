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

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.StringContains.containsString;

public class TenancyPrivateTenantEnabledTests extends SingleClusterTest {
    private static final Header AS_REST_API_USER = encodeBasicHeader("user_rest_api_access", "user_rest_api_access");
    private static final Header AS_ADMIN_USER = encodeBasicHeader("admin", "admin");
    private static final Header AS_USER = encodeBasicHeader("kirk", "kirk");
    private static final Header ON_USER_TENANT = new BasicHeader("securitytenant", "__user__");

    private static String createIndexPatternDoc(final String title) {
        return "{"
            + "\"type\" : \"index-pattern\","
            + "\"updated_at\" : \"2018-09-29T08:56:59.066Z\","
            + "\"index-pattern\" : {"
            + "\"title\" : \""
            + title
            + "\""
            + "}}";
    }

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }

    @Test
    public void testPrivateTenantDisabled_Update_EndToEnd() throws Exception {
        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig(),
            Settings.builder().put("plugins.security.restapi.roles_enabled.0", "security_rest_api_access").build(),
            true
        );

        final HttpResponse getSettingResponse = nonSslRestHelper().executeGetRequest(
            "/_plugins/_security/api/tenancy/config",
            AS_REST_API_USER
        );
        assertThat(getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getSettingResponse.findValueInJson("private_tenant_enabled"), equalTo("true"));

        HttpResponse getDashboardsinfoResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/dashboardsinfo", AS_ADMIN_USER);
        assertThat(getDashboardsinfoResponse.findValueInJson("private_tenant_enabled"), equalTo("true"));

        final HttpResponse createDocInGlobalTenantResponse = nonSslRestHelper().executePostRequest(
            ".kibana/_doc?refresh=true",
            createIndexPatternDoc("globalIndex"),
            AS_ADMIN_USER
        );
        assertThat(createDocInGlobalTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        final HttpResponse createDocInUserTenantResponse = nonSslRestHelper().executePostRequest(
            ".kibana/_doc?refresh=true",
            createIndexPatternDoc("userIndex"),
            ON_USER_TENANT,
            AS_USER
        );
        assertThat(createDocInUserTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        final HttpResponse searchInUserTenantWithPrivateTenantEnabled = nonSslRestHelper().executeGetRequest(
            ".kibana/_search",
            ON_USER_TENANT,
            AS_USER
        );
        assertThat(searchInUserTenantWithPrivateTenantEnabled.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(
            searchInUserTenantWithPrivateTenantEnabled.findValueInJson("hits.hits[0]._source.index-pattern.title"),
            equalTo("userIndex")
        );

        final HttpResponse disablePrivateTenantResponse = nonSslRestHelper().executePutRequest(
            "/_plugins/_security/api/tenancy/config",
            "{\"private_tenant_enabled\": \"false\"}",
            AS_REST_API_USER
        );
        assertThat(disablePrivateTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(disablePrivateTenantResponse.findValueInJson("private_tenant_enabled"), equalTo("false"));

        getDashboardsinfoResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/dashboardsinfo", AS_ADMIN_USER);
        assertThat(getDashboardsinfoResponse.findValueInJson("private_tenant_enabled"), equalTo("false"));

        final HttpResponse searchInUserTenantWithPrivateTenantDisabled = nonSslRestHelper().executeGetRequest(
            ".kibana/_search",
            ON_USER_TENANT,
            AS_USER
        );
        assertThat(searchInUserTenantWithPrivateTenantDisabled.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        assertThat(
            searchInUserTenantWithPrivateTenantDisabled.findValueInJson("error.reason"),
            containsString("no permissions for [indices:data/read/search] and User")
        );

    }

}
