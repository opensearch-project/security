/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.privileges.int_tests;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1;
import org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.matcher.RestMatchers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2.SYSTEM_INDEX_2;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(Parameterized.class)
public class PluginSystemIndexIntTests {

    final LocalCluster cluster;
    final ClusterConfig clusterConfig;

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER_ADMIN)
            .plugin(SystemIndexPlugin1.class, SystemIndexPlugin2.class);
    }

    @ClassRule
    public static final ClusterConfig.ClusterInstances clusters = new ClusterConfig.ClusterInstances(
        PluginSystemIndexIntTests::clusterBuilder
    );

    @Parameters(name = "{0}")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();

        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            result.add(new Object[] { clusterConfig });
        }
        return result;
    }

    public PluginSystemIndexIntTests(ClusterConfig clusterConfig) {
        this.clusterConfig = clusterConfig;
        this.cluster = clusters.get(clusterConfig);
    }

    @Before
    public void setup() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(SYSTEM_INDEX_1);
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
    public void testPluginShouldBeAbleToCreateSystemIndexButUserShouldNotBeAbleToIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-index/" + SYSTEM_INDEX_1 + "?runAs=user");

            assertThat(response, RestMatchers.isForbidden("/error/root_cause/0/reason", "no permissions for [] and User [name=admin"));
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
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            HttpResponse searchResponse = client.get("search-on-system-index/" + SYSTEM_INDEX_1);

            assertThat(searchResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));
        }
    }

    @Test
    public void testPluginShouldBeAbleGetOnItsSystemIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));

            HttpResponse searchResponse = client.get("search-on-system-index/" + SYSTEM_INDEX_1);

            assertThat(searchResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(searchResponse.getIntFromJsonBody("/hits/total/value"), equalTo(2));

            String docId = searchResponse.getTextFromJsonBody("/hits/hits/0/_id");

            HttpResponse getResponse = client.get("get-on-system-index/" + SYSTEM_INDEX_1 + "/" + docId);

            assertThat(getResponse.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
        }
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
    }

    @Test
    public void testPluginShouldNotBeAbleToBulkIndexDocumentIntoMixOfSystemIndexWhereAtLeastOneDoesNotBelongToPlugin() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.put(SYSTEM_INDEX_1);
            client.put(SYSTEM_INDEX_2);
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
    public void testPluginShouldNotBeAbleToSearchOnMixOfSystemIndexWhereAtLeastOneDoesNotBelongToPlugin() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.put(SYSTEM_INDEX_1);
            client.put(SYSTEM_INDEX_2);
        }
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("search-on-mixed-system-index");

            assertThat(
                response.getBody(),
                containsString(
                    "no permissions for [] and User [name=plugin:org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1"
                )
            );
        }
    }
}
