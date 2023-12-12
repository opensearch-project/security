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

import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;

public class RenameFieldResponseProcessorTest extends AbstractDlsFlsTest {
    private final String ROLES_FILE = "roles_flsdls_rename_processor.yml";
    private final String ROLES_MAPPINGS_FILE = "roles_mapping_flsdls_rename_processor.yml";
    private final Header asUserA = encodeBasicHeader("user_aaa", "password");
    private final Header asAdmin = encodeBasicHeader("admin", "admin");
    private final String emptyQuery = "{ \"query\": { \"match_all\": {} } }";

    protected void populateData(final Client tc) {
        // Insert in some dummy flight data
        tc.index(
            new IndexRequest("flights").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{"
                        + "\"FlightNum\": \"9HY9SWR\","
                        + "\"DestAirportID\": \"SYD\","
                        + "\"Dest\": \"Sydney Kingsford Smith International Airport\","
                        + "\"DestCountry\": \"AU\","
                        + "\"OriginAirportID\": \"FRA\","
                        + "\"Origin\": \"Frankfurt am Main Airport\","
                        + "\"OriginCountry\": \"DE\","
                        + "\"FlightDelay\" : true,"
                        + "\"Canceled\": true"
                        + "}",
                    XContentType.JSON
                )
        ).actionGet();
        tc.index(
            new IndexRequest("flights").id("1")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{"
                        + "\"FlightNum\": \"X98CCZO\","
                        + "\"DestAirportID\": \"VE05\","
                        + "\"Dest\": \"Venice Marco Polo Airport\","
                        + "\"DestCountry\": \"IT\","
                        + "\"OriginAirportID\": \"CPT\","
                        + "\"Origin\": \"Cape Town International Airport\","
                        + "\"OriginCountry\": \"ZA\","
                        + "\"FlightDelay\" : false,"
                        + "\"Canceled\": false"
                        + "}",
                    XContentType.JSON
                )
        ).actionGet();
        tc.index(
            new IndexRequest("flights").id("2")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{"
                        + "\"FlightNum\": \"UFK2WIZ\","
                        + "\"DestAirportID\": \"SYD\","
                        + "\"Dest\": \"Venice Marco Polo Airport\","
                        + "\"DestCountry\": \"IT\","
                        + "\"OriginAirportID\": \"FRA\","
                        + "\"Origin\": \"Venice Marco Polo Airport\","
                        + "\"OriginCountry\": \"IT\","
                        + "\"FlightDelay\" : false,"
                        + "\"Canceled\": true"
                        + "}",
                    XContentType.JSON
                )
        ).actionGet();
    }

    @Test
    public void testMaskedField() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE),
            ClusterConfiguration.SEARCH_PIPELINE
        );

        HttpResponse res;
        res = rh.executePostRequest("/flights/_search", emptyQuery, asUserA);
        assertThat(res.findValueInJson("hits.hits[0]._source.FlightNum"), not(equalTo("9HY9SWR")));
        String testRenameMaskedFieldPipeline = "{"
            + "\"description\": \"A pipeline to rename masked field 'FlightNum' to 'FlightNumNew'\","
            + "\"response_processors\": ["
            + "{"
            + "\"rename_field\": {"
            + "\"target_field\": \"FlightNumNew\","
            + "\"field\": \"FlightNum\""
            + "}"
            + "}"
            + "]"
            + "}";
        res = rh.executePutRequest("/_search/pipeline/test-rename-masked-field", testRenameMaskedFieldPipeline, asAdmin);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Search with this pipeline should succeed and the value of the new field "FlightNumNew" should also be masked
        res = rh.executePostRequest("/flights/_search?search_pipeline=test-rename-masked-field&size=1", emptyQuery, asUserA);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.findValueInJson("hits.hits[0]._source.FlightNumNew"), not(equalTo("9HY9SWR")));
    }

    @Test
    public void testFieldLevelSecurity() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE),
            ClusterConfiguration.SEARCH_PIPELINE
        );

        HttpResponse res;
        String testFieldLevelSecurityPipeline = "{"
            + "\"description\": \"A pipeline to rename 'DestCountry' to 'DestCountryNew'\","
            + "\"response_processors\": ["
            + "{"
            + "\"rename_field\": {"
            + "\"target_field\": \"DestCountryNew\","
            + "\"field\": \"DestCountry\""
            + "}"
            + "}"
            + "]"
            + "}";
        res = rh.executePutRequest("/_search/pipeline/test-field-level-security", testFieldLevelSecurityPipeline, asAdmin);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Search with this pipeline should fail because "DestCountry" is restricted under FLS
        res = rh.executePostRequest("/flights/_search?search_pipeline=test-field-level-security&size=1", emptyQuery, asUserA);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
    }

    @Test
    public void testFieldLevelSecurityReverse() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE),
            ClusterConfiguration.SEARCH_PIPELINE
        );

        HttpResponse res;
        String testFieldLevelSecurityReversePipeline = "{"
            + "\"description\": \"A pipeline to rename an accessible field name to an inaccessible field name\","
            + "\"response_processors\": ["
            + "{"
            + "\"rename_field\": {"
            + "\"target_field\": \"DestCountry\","
            + "\"field\": \"Dest\""
            + "}"
            + "}"
            + "]"
            + "}";
        res = rh.executePutRequest("/_search/pipeline/test-field-level-security-reverse", testFieldLevelSecurityReversePipeline, asAdmin);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Search with this pipeline should succeed and the value of the new "DestCountry" field should be the previous value of "Dest"
        res = rh.executePostRequest("/flights/_search?search_pipeline=test-field-level-security-reverse&size=1", emptyQuery, asUserA);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.findValueInJson("hits.hits[0]._source.DestCountry"), equalTo("Sydney Kingsford Smith International Airport"));
    }

    @Test
    public void testDocumentLevelSecurity() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE),
            ClusterConfiguration.SEARCH_PIPELINE
        );

        HttpResponse res;
        String testDocumentLevelSecurityPipeline = "{"
            + "\"description\": \"A pipeline to rename a DLS restricted field name to a new field name\","
            + "\"response_processors\": ["
            + "{"
            + "\"rename_field\": {"
            + "\"target_field\": \"FlightDelayNew\","
            + "\"field\": \"FlightDelay\""
            + "}"
            + "}"
            + "]"
            + "}";
        res = rh.executePutRequest("/_search/pipeline/test-document-level-security", testDocumentLevelSecurityPipeline, asAdmin);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Search with this pipeline should succeed and should only return documents where "FlightDelay" is true and the new
        // "FlightDelayNew" will also be true
        res = rh.executePostRequest("/flights/_search?search_pipeline=test-document-level-security&size=3", emptyQuery, asUserA);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.findValueInJson("hits.total.value"), equalTo("1"));
        assertThat(res.findValueInJson("hits.hits[0]._source.FlightDelayNew"), equalTo("true"));
    }

    @Test
    public void testDocumentLevelSecurityReverse() throws Exception {
        setup(
            new DynamicSecurityConfig().setSecurityRoles(ROLES_FILE).setSecurityRolesMapping(ROLES_MAPPINGS_FILE),
            ClusterConfiguration.SEARCH_PIPELINE
        );

        HttpResponse res;
        String testDocumentLevelSecurityReversePipeline = "{"
            + "\"description\": \"A pipeline to rename an accessible field name to a DLS restricted field name\","
            + "\"response_processors\": ["
            + "{"
            + "\"rename_field\": {"
            + "\"target_field\": \"FlightDelay\","
            + "\"field\": \"Canceled\""
            + "}"
            + "}"
            + "]"
            + "}";
        res = rh.executePutRequest(
            "/_search/pipeline/test-document-level-security-reverse",
            testDocumentLevelSecurityReversePipeline,
            asAdmin
        );
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));

        // Search with this pipeline should succeed and should only return documents where "FlightDelay" is true in the original document
        // and the new "FlightDelay"
        // will also be true
        res = rh.executePostRequest("/flights/_search?search_pipeline=test-document-level-security-reverse&size=3", emptyQuery, asUserA);
        assertThat(res.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertThat(res.findValueInJson("hits.total.value"), equalTo("1"));
        assertThat(res.findValueInJson("hits.hits[0]._source.FlightDelay"), equalTo("true"));
    }
}
