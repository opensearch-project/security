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

package org.opensearch.security.dlic.dlsfls;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.StringContains.containsString;

public class FlsIndexingTests extends AbstractDlsFlsTest {

    protected void populateData(final Client tc) {
        // Create several documents in different indices with shared field names,
        // different roles will have different levels of FLS restrictions
        tc.index(
            new IndexRequest("yellow-pages").id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"phone-all\":1001,\"phone-some\":1002,\"phone-one\":1003}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("green-pages").id("2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"phone-all\":2001,\"phone-some\":2002,\"phone-one\":2003}", XContentType.JSON)
        ).actionGet();
        tc.index(
            new IndexRequest("blue-book").id("3")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"phone-all\":3001,\"phone-some\":3002,\"phone-one\":3003}", XContentType.JSON)
        ).actionGet();

        // Seperate index used to test aliasing
        tc.index(new IndexRequest(".hidden").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{}", XContentType.JSON)).actionGet();
    }

    private Header asPhoneOneUser = encodeBasicHeader("user_aaa", "password");
    private Header asPhoneSomeUser = encodeBasicHeader("user_bbb", "password");
    private Header asPhoneAllUser = encodeBasicHeader("user_ccc", "password");

    private final String searchQuery = "/*/_search?filter_path=hits.hits&pretty";

    @Test
    public void testSingleIndexFlsApplied() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles("roles_fls_indexing.yml").setSecurityRolesMapping("roles_mapping_fls_indexing.yml")
        );

        final HttpResponse phoneOneFilteredResponse = rh.executeGetRequest(searchQuery, asPhoneOneUser);
        assertThat(phoneOneFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("1003")));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1001"));

        assertThat(phoneOneFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("2002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("2001"));

        assertThat(phoneOneFilteredResponse.getBody(), containsString("3003"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("3002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("3001"));
    }

    @Test
    public void testSingleIndexFlsAppliedForLimitedResults() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles("roles_fls_indexing.yml").setSecurityRolesMapping("roles_mapping_fls_indexing.yml")
        );

        final HttpResponse phoneOneFilteredResponse = rh.executeGetRequest(
            "/yellow-pages/_search?filter_path=hits.hits&pretty",
            asPhoneOneUser
        );
        assertThat(phoneOneFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("1003")));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1001"));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2003")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2002")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2001")));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3003")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3002")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3001")));
    }

    @Test
    public void testSeveralIndexFlsApplied() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles("roles_fls_indexing.yml").setSecurityRolesMapping("roles_mapping_fls_indexing.yml")
        );

        final HttpResponse phoneSomeFilteredResponse = rh.executeGetRequest(searchQuery, asPhoneSomeUser);
        assertThat(phoneSomeFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("1003"));
        assertThat(phoneSomeFilteredResponse.getBody(), not(containsString("1002")));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("1001"));

        assertThat(phoneSomeFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneSomeFilteredResponse.getBody(), not(containsString("2002")));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("2001"));

        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3003"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3002"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3001"));
    }

    @Test
    public void testAllIndexFlsApplied() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles("roles_fls_indexing.yml").setSecurityRolesMapping("roles_mapping_fls_indexing.yml")
        );

        final HttpResponse phoneAllFilteredResponse = rh.executeGetRequest(searchQuery, asPhoneAllUser);
        assertThat(phoneAllFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("1001")));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("2002"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("2001")));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("3003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("3002"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("3001")));
    }

    @Test
    public void testAllIndexFlsAppliedWithAlias() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles("roles_fls_indexing.yml").setSecurityRolesMapping("roles_mapping_fls_indexing.yml")
        );

        final HttpResponse createAlias = rh.executePostRequest(
            "_aliases",
            "{\"actions\":[{\"add\":{\"index\":\".hidden\",\"alias\":\"ducky\"}}]}",
            asPhoneAllUser
        );
        assertThat(createAlias.getStatusCode(), equalTo(HttpStatus.SC_OK));

        final HttpResponse phoneAllFilteredResponse = rh.executeGetRequest(searchQuery, asPhoneAllUser);
        assertThat(phoneAllFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("1001")));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("2002"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("2001")));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("3003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("3002"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("3001")));
    }
}
