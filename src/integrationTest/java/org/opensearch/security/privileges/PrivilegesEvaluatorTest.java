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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.script.mustache.MustacheModulePlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
* This is a port for the test
* org.opensearch.security.privileges.PrivilegesEvaluatorTest to the new test
* framework for direct comparison
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PrivilegesEvaluatorTest {

    protected final static TestSecurityConfig.User NEGATIVE_LOOKAHEAD = new TestSecurityConfig.User("negative_lookahead_user").roles(
        new Role("negative_lookahead_role").indexPermissions("read").on("/^(?!t.*).*/").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User NEGATED_REGEX = new TestSecurityConfig.User("negated_regex_user").roles(
        new Role("negated_regex_role").indexPermissions("read").on("/^[a-z].*/").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User SEARCH_TEMPLATE = new TestSecurityConfig.User("search_template_user").roles(
        new Role("search_template_role").indexPermissions("read").on("services").clusterPermissions("cluster_composite_ops")
    );

    protected final static TestSecurityConfig.User LIMITED_USER = new TestSecurityConfig.User("limited*_user").roles(
        new Role("limited*_user").indexPermissions("*").on("limited*").clusterPermissions("cluster_monitor")
    );

    private String TEST_QUERY =
        "{\"source\":{\"query\":{\"match\":{\"service\":\"{{service_name}}\"}}},\"params\":{\"service_name\":\"Oracle\"}}";

    private String TEST_DOC = "{\"source\": {\"title\": \"Spirited Away\"}}";

    private String LIMITED_LOGS_INDEX_TEMPLATE =
        "{\"index_patterns\": [ \"limited-logs\" ], \"data_stream\": { }, \"priority\": 200, \"template\": {\"settings\": { } } }";

    private String LIMITED_LOGS_DATA_STREAM =
        "{\"index_patterns\": [ \"limited-logs\" ], \"data_stream\": {\"timestamp_field\": {\"name\": \"request_time\"} }, \"priority\": 200, \"template\": {\"settings\": { } } }";

    private String UNLIMITED_LOGS_INDEX_TEMPLATE =
        "{\"index_patterns\": [ \"unlimited-logs\" ], \"data_stream\": { }, \"priority\": 200, \"template\": {\"settings\": { } } }";

    private String UNLIMITED_LOGS_DATA_STREAM =
        "{\"index_patterns\": [ \"unlimited-logs\" ], \"data_stream\": {\"timestamp_field\": {\"name\": \"request_time\"} }, \"priority\": 200, \"template\": {\"settings\": { } } }";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(NEGATIVE_LOOKAHEAD, NEGATED_REGEX, SEARCH_TEMPLATE, TestSecurityConfig.User.USER_ADMIN, LIMITED_USER)
        .plugin(MustacheModulePlugin.class)
        .build();

    @Test
    public void testNegativeLookaheadPattern() throws Exception {

        try (TestRestClient client = cluster.getRestClient(NEGATIVE_LOOKAHEAD)) {
            assertThat(client.get("*/_search").getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            assertThat(client.get("r*/_search").getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    public void testRegexPattern() throws Exception {

        try (TestRestClient client = cluster.getRestClient(NEGATED_REGEX)) {
            assertThat(client.get("*/_search").getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
            assertThat(client.get("r*/_search").getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

    }

    @Test
    public void testSearchTemplateRequestSuccess() {
        // Insert doc into services index with admin user
        try (TestRestClient client = cluster.getRestClient(TestSecurityConfig.User.USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.postJson("services/_doc", TEST_DOC);
            assertThat(response.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        }

        try (TestRestClient client = cluster.getRestClient(SEARCH_TEMPLATE)) {
            final String searchTemplateOnServicesIndex = "services/_search/template";
            final TestRestClient.HttpResponse searchTemplateOnAuthorizedIndexResponse = client.getWithJsonBody(
                searchTemplateOnServicesIndex,
                TEST_QUERY
            );
            assertThat(searchTemplateOnAuthorizedIndexResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }
    }

    @Test
    public void testSearchTemplateRequestUnauthorizedIndex() {
        try (TestRestClient client = cluster.getRestClient(SEARCH_TEMPLATE)) {
            final String searchTemplateOnMoviesIndex = "movies/_search/template";
            final TestRestClient.HttpResponse searchTemplateOnUnauthorizedIndexResponse = client.getWithJsonBody(
                searchTemplateOnMoviesIndex,
                TEST_QUERY
            );
            assertThat(searchTemplateOnUnauthorizedIndexResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    @Test
    public void testSearchTemplateRequestUnauthorizedAllIndices() {
        try (TestRestClient client = cluster.getRestClient(SEARCH_TEMPLATE)) {
            final String searchTemplateOnAllIndices = "_search/template";
            final TestRestClient.HttpResponse searchOnAllIndicesResponse = client.getWithJsonBody(searchTemplateOnAllIndices, TEST_QUERY);
            assertThat(searchOnAllIndicesResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    @Test
    public void testGetAliasShouldSucceedWithIndexPermissionsFailWithout() {
        // Get aliases following a pattern they have access to should succeed
        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            final String catAliasesOnServices = "_cat/aliases/limited*";
            final TestRestClient.HttpResponse searchTemplateOnAuthorizedIndexResponse = client.get(catAliasesOnServices);
            assertThat(searchTemplateOnAuthorizedIndexResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

        // Get all aliases should fail
        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            final String catAliasesOnAll = "_cat/aliases";
            final TestRestClient.HttpResponse searchTemplateOnAuthorizedIndexResponse = client.get(catAliasesOnAll);
            assertThat(searchTemplateOnAuthorizedIndexResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }

    @Test
    public void testRolloverShouldSucceedWithIndexPermissionsFailWithout() {
        // Create two data streams and verify admin can rollover both of them
        try (TestRestClient client = cluster.getRestClient(TestSecurityConfig.User.USER_ADMIN)) {

            client.putJson("_index_template/limited-logs-template", LIMITED_LOGS_INDEX_TEMPLATE);

            client.putJson("_data_stream/limited-logs", LIMITED_LOGS_DATA_STREAM);

            client.putJson("_index_template/unlimited-logs-template", UNLIMITED_LOGS_INDEX_TEMPLATE);

            client.putJson("_data_stream/unlimited-logs", UNLIMITED_LOGS_DATA_STREAM);
            final String catAliasesOnServices = "limited-logs/_rollover";
            final TestRestClient.HttpResponse searchTemplateOnAuthorizedIndexResponse = client.post(catAliasesOnServices);
            assertThat(searchTemplateOnAuthorizedIndexResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

            final String moviescatAliasesOnServices = "unlimited-logs/_rollover";
            final TestRestClient.HttpResponse searchTemplateOnAuthorizedIndexResponsem = client.post(moviescatAliasesOnServices);
            assertThat(searchTemplateOnAuthorizedIndexResponsem.getStatusCode(), equalTo(HttpStatus.SC_OK));
        }

        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            // Limited user can rollover limited-logs
            final String rolloverLimitedLogs = "limited-logs/_rollover";
            final TestRestClient.HttpResponse rolloverLimitedLogsResponse = client.post(rolloverLimitedLogs);
            assertThat(rolloverLimitedLogsResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

            // Limited user cannot rollover unlimited-logs
            final String rolloverUnlimitedLogs = "unlimited-logs/_rollover";
            final TestRestClient.HttpResponse rolloverUnlimitedLogsResponse = client.post(rolloverUnlimitedLogs);
            assertThat(rolloverUnlimitedLogsResponse.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }
}
