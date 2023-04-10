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
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.Test;

import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.StringContains.containsString;

public class TenancyMultitenancyEnabledTests extends SingleClusterTest {
    private final Header asAdminUser = encodeBasicHeader("admin", "admin");
    private final Header asUser = encodeBasicHeader("kirk", "kirk");
    private final Header onUserTenant = new BasicHeader("securitytenant", "__user__");
    
    private static String createIndexPatternDoc(final String title) {
        return "{"+
        "\"type\" : \"index-pattern\","+
        "\"updated_at\" : \"2018-09-29T08:56:59.066Z\","+
        "\"index-pattern\" : {"+
            "\"title\" : \"" + title + "\""+
            "}}";
    } 

    @Override
    protected String getResourceFolder() {
        return "multitenancy";
    }

    @Test
    public void testMultitenancyDisabled_endToEndTest() throws Exception {
        setup();

        final HttpResponse getSettingResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/api/tenancy/config", asAdminUser);
        assertThat(getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(getSettingResponse.findValueInJson("multitenancy_enabled"), equalTo("true"));

        HttpResponse getDashboardsinfoResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/dashboardsinfo", asAdminUser);
        assertThat(getDashboardsinfoResponse.findValueInJson("multitenancy_enabled"),equalTo("true"));

        final HttpResponse createDocInGlobalTenantResponse = nonSslRestHelper().executePostRequest(".kibana/_doc?refresh=true", createIndexPatternDoc("globalIndex"), asAdminUser);
        assertThat(createDocInGlobalTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        final HttpResponse createDocInUserTenantResponse = nonSslRestHelper().executePostRequest(".kibana/_doc?refresh=true", createIndexPatternDoc("userIndex"), onUserTenant, asAdminUser);
        assertThat(createDocInUserTenantResponse.getStatusCode(), equalTo(HttpStatus.SC_CREATED));

        final HttpResponse searchInUserTenantWithMutlitenancyEnabled = nonSslRestHelper().executeGetRequest(".kibana/_search", onUserTenant, asAdminUser);
        assertThat(searchInUserTenantWithMutlitenancyEnabled.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(searchInUserTenantWithMutlitenancyEnabled.findValueInJson("hits.hits[0]._source.index-pattern.title"), equalTo("userIndex"));

        final HttpResponse updateMutlitenancyToDisabled = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"multitenancy_enabled\": \"false\"}", asAdminUser);
        assertThat(updateMutlitenancyToDisabled.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(updateMutlitenancyToDisabled.findValueInJson("multitenancy_enabled"), equalTo("false"));

        getDashboardsinfoResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/dashboardsinfo", asAdminUser);
        assertThat(getDashboardsinfoResponse.findValueInJson("multitenancy_enabled"),equalTo("false"));

        final HttpResponse searchInUserTenantWithMutlitenancyDisabled = nonSslRestHelper().executeGetRequest(".kibana/_search", onUserTenant, asAdminUser);
        assertThat(searchInUserTenantWithMutlitenancyDisabled.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(searchInUserTenantWithMutlitenancyDisabled.findValueInJson("hits.hits[0]._source.index-pattern.title"), equalTo("globalIndex"));
    }

    @Test
    public void testForbiddenAccess() throws Exception {
        setup();

        final HttpResponse getSettingResponse = nonSslRestHelper().executeGetRequest("/_plugins/_security/api/tenancy/config", asUser);
        assertThat(getSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        assertThat(getSettingResponse.findValueInJson("error.reason"), containsString("no permissions for [cluster:feature/tenancy/config/read]"));

        final HttpResponse updateSettingResponse = nonSslRestHelper().executePutRequest("/_plugins/_security/api/tenancy/config", "{\"multitenancy_enabled\": \"false\"}", asUser);
        assertThat(updateSettingResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        assertThat(updateSettingResponse.findValueInJson("error.reason"), containsString("no permissions for [cluster:feature/tenancy/config/update]"));
    }
}
