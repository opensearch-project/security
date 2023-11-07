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

import java.util.function.BiFunction;
import java.util.function.Consumer;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.StringContains.containsString;

public class FlsFlatTests extends AbstractDlsFlsTest {

    private final String ROLES_FILE = "roles_fls_flat.yml";
    private final String ROLES_MAPPINGS_FILE = "roles_mapping_fls_indexing.yml";

    protected void populateData(final Client tc) {
        // Create several documents in different indices with shared field names,
        // different roles will have different levels of FLS restrictions

        final BiFunction<XContentBuilder, String, XContentBuilder> addFlatField = (builder, fieldName) -> {
            try {
                return builder.startObject(fieldName)
                    .startObject("properties")
                    .startObject("field")
                    .field("type", "flat_object")
                    .endObject()
                    .endObject()
                    .endObject();
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };

        XContentBuilder builder = null;
        try {
            builder = XContentFactory.jsonBuilder().startObject();
            builder = addFlatField.apply(builder, "phone-all");
            builder = addFlatField.apply(builder, "phone-some");
            builder = addFlatField.apply(builder, "phone-one");
            builder.endObject();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        final String mappings = builder.toString();

        final Consumer<String> createIndexWithMapping = (indexName) -> {
            final CreateIndexRequest createIndex = new CreateIndexRequest(indexName);
            createIndex.settings(mappings, XContentType.JSON);
            tc.admin().indices().create(createIndex);
        };

        // Field Schema
        // - phone-all.areaCode: {docId}001
        // - phone-some.areaCode: {docId}002
        // - phone-one.areaCode: {docId}002
        // Local number == areaCode + 90
        // Filtering is only done on local number
        createIndexWithMapping.accept("yellow-page");
        tc.index(
            new IndexRequest("yellow-pages").id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"phone-all\": {\"areaCode\": 1001, \"localNumber\": 1091 },\"phone-some\":{\"areaCode\": 1002, \"localNumber\": 1092 },\"phone-one\":{\"areaCode\": 1003, \"localNumber\": 1093 }}",
                    XContentType.JSON
                )
        ).actionGet();
        createIndexWithMapping.accept("green-page");
        tc.index(
            new IndexRequest("green-pages").id("2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"phone-all\": {\"areaCode\": 2001, \"localNumber\": 2091 },\"phone-some\":{\"areaCode\": 2002, \"localNumber\": 2092 },\"phone-one\":{\"areaCode\": 2003, \"localNumber\": 2093 }}",
                    XContentType.JSON
                )
        ).actionGet();
        createIndexWithMapping.accept("blue-book");
        tc.index(
            new IndexRequest("blue-book").id("3")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"phone-all\": {\"areaCode\": 3001, \"localNumber\": 3091 },\"phone-some\":{\"areaCode\": 3002, \"localNumber\": 3092 },\"phone-one\":{\"areaCode\": 3003, \"localNumber\": 3093 }}",
                    XContentType.JSON
                )
        ).actionGet();

        // Seperate index used to test aliasing
        tc.index(new IndexRequest(".hidden").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{}", XContentType.JSON)).actionGet();
    }

    private Header asPhoneOneUser = encodeBasicHeader("user_aaa", "password");
    private Header asPhoneSomeUser = encodeBasicHeader("user_bbb", "password");
    private Header asPhoneAllUser = encodeBasicHeader("user_ccc", "password");

    private final String searchQuery = "/*/_search?filter_path=hits.hits&pretty";

    @Test
    public void testSingleFlatFieldFlsApplied() throws Exception {
        setup(new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE));

        final HttpResponse phoneOneFilteredResponse = rh.executeGetRequest(searchQuery, asPhoneOneUser);
        assertThat(phoneOneFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1003"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1001"));

        assertThat(phoneOneFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("2002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("2001"));

        assertThat(phoneOneFilteredResponse.getBody(), containsString("3003"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("3002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("3001"));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("1093")));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1092"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1091"));

        assertThat(phoneOneFilteredResponse.getBody(), containsString("2093"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("2092"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("2091"));

        assertThat(phoneOneFilteredResponse.getBody(), containsString("3093"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("3092"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("3091"));
    }

    @Test
    public void testSingleFlatFieldFlsAppliedForLimitedResults() throws Exception {
        setup(new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE));

        final HttpResponse phoneOneFilteredResponse = rh.executeGetRequest(
            "/yellow-pages/_search?filter_path=hits.hits&pretty",
            asPhoneOneUser
        );
        assertThat(phoneOneFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1003"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1001"));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2003")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2002")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2001")));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3003")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3002")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3001")));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("1093")));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1092"));
        assertThat(phoneOneFilteredResponse.getBody(), containsString("1091"));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2093")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2092")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("2091")));

        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3093")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3092")));
        assertThat(phoneOneFilteredResponse.getBody(), not(containsString("3091")));
    }

    @Test
    public void testSeveralFlatFieldFlsApplied() throws Exception {
        setup(new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE));

        final HttpResponse phoneSomeFilteredResponse = rh.executeGetRequest(searchQuery, asPhoneSomeUser);
        assertThat(phoneSomeFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("1003"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("1001"));

        assertThat(phoneSomeFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("2002"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("2001"));

        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3003"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3002"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3001"));

        assertThat(phoneSomeFilteredResponse.getBody(), containsString("1093"));
        assertThat(phoneSomeFilteredResponse.getBody(), not(containsString("1092")));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("1091"));

        assertThat(phoneSomeFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneSomeFilteredResponse.getBody(), not(containsString("2092")));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("2091"));

        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3093"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3092"));
        assertThat(phoneSomeFilteredResponse.getBody(), containsString("3091"));
    }

    @Test
    public void testAllFlatFieldFlsApplied() throws Exception {
        setup(new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE));

        final HttpResponse phoneAllFilteredResponse = rh.executeGetRequest(searchQuery, asPhoneAllUser);
        assertThat(phoneAllFilteredResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1002"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1001"));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("2003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("2002"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("2001"));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("3003"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("3002"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("3001"));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("1093"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("1092"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("1091")));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("2093"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("2092"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("2091")));

        assertThat(phoneAllFilteredResponse.getBody(), containsString("3093"));
        assertThat(phoneAllFilteredResponse.getBody(), containsString("3092"));
        assertThat(phoneAllFilteredResponse.getBody(), not(containsString("3091")));
    }
}
