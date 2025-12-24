/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.systemindex;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.matcher.RestMatchers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2.SYSTEM_INDEX_2;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

public class SystemIndexTests {

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(USER_ADMIN)
        .plugin(SystemIndexPlugin1.class, SystemIndexPlugin2.class)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true
            )
        )
        .build();

    @Before
    public void setup() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(".system-index1");
        }
    }

    @Test
    public void adminShouldNotBeAbleToDeleteSecurityIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.delete(".opendistro_security");

            assertThat(response.getStatusCode(), equalTo(RestStatus.FORBIDDEN.getStatus()));

            // Create regular index
            client.put("test-index");

            // regular user can delete non-system index
            HttpResponse response2 = client.delete("test-index");

            assertThat(response2.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            // regular use can create system index
            HttpResponse response3 = client.put(".system-index1");

            assertThat(response3.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            // regular user cannot delete system index
            HttpResponse response4 = client.delete(".system-index1");

            assertThat(response4.getStatusCode(), equalTo(RestStatus.FORBIDDEN.getStatus()));
        }
    }

    @Test
    public void testPluginShouldBeAbleToIndexDocumentIntoItsSystemIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(response.getBody(), containsString("{\"acknowledged\":true}"));
        }
    }

    @Test
    public void testPluginShouldNotBeAbleToIndexDocumentIntoSystemIndexRegisteredByOtherPlugin() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-index/" + SYSTEM_INDEX_2);

            assertThat(
                response,
                RestMatchers.isForbidden(
                    "/error/root_cause/0/reason",
                    "no permissions for [] and User [name=plugin:org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1"
                )
            );
        }
    }

    @Test
    public void testPluginShouldBeAbleToCreateSystemIndexButUserShouldNotBeAbleToIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-index/" + SYSTEM_INDEX_1 + "?runAs=user");

            assertThat(response, RestMatchers.isForbidden("/error/root_cause/0/reason", "no permissions for [] and User [name=admin"));
        }
    }

    @Test
    public void testPluginShouldNotBeAbleToRunClusterActions() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("try-cluster-health/plugin");

            assertThat(
                response,
                RestMatchers.isForbidden(
                    "/error/root_cause/0/reason",
                    "no permissions for [cluster:monitor/health] and User [name=plugin:org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1"
                )
            );
        }
    }

    @Test
    public void testAdminUserShouldBeAbleToRunClusterActions() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("try-cluster-health/user");

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
        }
    }

    @Test
    public void testAuthenticatedUserShouldBeAbleToRunClusterActions() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("try-cluster-health/default");

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
        }
    }

    @Test
    public void testPluginShouldBeAbleToBulkIndexDocumentIntoItsSystemIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
        }
    }

    @Test
    public void testPluginShouldBeAbleSearchOnItsSystemIndex() {
        JsonNode searchResponse1;
        JsonNode searchResponse2;
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            HttpResponse searchResponse = client.get("search-on-system-index/" + SYSTEM_INDEX_1);

            assertThat(searchResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            searchResponse1 = searchResponse.bodyAsJsonNode();
        }

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse searchResponse = client.get(SYSTEM_INDEX_1 + "/_search");

            assertThat(searchResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            searchResponse2 = searchResponse.bodyAsJsonNode();
        }

        JsonNode hits1 = searchResponse1.get("hits");
        JsonNode hits2 = searchResponse2.get("hits");
        assertThat(hits1.toPrettyString(), equalTo(hits2.toPrettyString()));
    }

    @Test
    public void testPluginShouldBeAbleGetOnItsSystemIndex() {
        JsonNode getResponse1;
        JsonNode getResponse2;
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            HttpResponse searchResponse = client.get("search-on-system-index/" + SYSTEM_INDEX_1);

            assertThat(searchResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            String docId = searchResponse.getTextFromJsonBody("/hits/hits/0/_id");

            HttpResponse getResponse = client.get("get-on-system-index/" + SYSTEM_INDEX_1 + "/" + docId);

            getResponse1 = getResponse.bodyAsJsonNode();
        }

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse searchResponse = client.get(SYSTEM_INDEX_1 + "/_search");

            assertThat(searchResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            String docId = searchResponse.getTextFromJsonBody("/hits/hits/0/_id");

            HttpResponse getResponse = client.get(SYSTEM_INDEX_1 + "/_doc/" + docId);

            getResponse2 = getResponse.bodyAsJsonNode();
        }
        assertThat(getResponse1.toPrettyString(), equalTo(getResponse2.toPrettyString()));
    }

    @Test
    public void testPluginShouldBeAbleUpdateOnItsSystemIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            HttpResponse searchResponse = client.get("search-on-system-index/" + SYSTEM_INDEX_1);

            assertThat(searchResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            String docId = searchResponse.getTextFromJsonBody("/hits/hits/0/_id");

            HttpResponse updateResponse = client.put("update-on-system-index/" + SYSTEM_INDEX_1 + "/" + docId);

            updateResponse.assertStatusCode(RestStatus.OK.getStatus());
        }

        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse searchResponse = client.get(SYSTEM_INDEX_1 + "/_search");

            searchResponse.assertStatusCode(RestStatus.OK.getStatus());

            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            String docId = searchResponse.getTextFromJsonBody("/hits/hits/0/_id");

            HttpResponse getResponse = client.get(SYSTEM_INDEX_1 + "/_doc/" + docId);

            assertThat("{\"content\":3}", equalTo(getResponse.bodyAsJsonNode().get("_source").toString()));
        }
    }

    @Test
    public void testPluginShouldNotBeAbleToBulkIndexDocumentIntoMixOfSystemIndexWhereAtLeastOneDoesNotBelongToPlugin() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.put(".system-index1");
            client.put(".system-index2");
        }
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-mixed-index");

            assertThat(
                response.getBody(),
                containsString(
                    "no permissions for [] and User [name=plugin:org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1"
                )
            );
        }
    }

    @Test
    public void regularUserShouldGetNoResultsWhenSearchingSystemIndex() {
        // Create system index and index a dummy document as the super admin user, data returned to super admin
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse response1 = client.put(".system-index1");

            assertThat(response1.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            String doc = "{\"field\":\"value\"}";
            HttpResponse adminPostResponse = client.postJson(".system-index1/_doc/1?refresh=true", doc);
            assertThat(adminPostResponse.getStatusCode(), equalTo(RestStatus.CREATED.getStatus()));
            HttpResponse response2 = client.get(".system-index1/_search");

            assertThat(response2.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(response2.getBody(), response2.getBody().contains("\"hits\":{\"total\":{\"value\":1,\"relation\":\"eq\"}"));
        }

        // Regular users should not be able to read it
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            // regular user cannot read system index
            HttpResponse response1 = client.get(".system-index1/_search");

            assertThat(response1.getBody(), response1.getBody().contains("\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"}"));
        }
    }
}
