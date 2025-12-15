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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

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
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.systemindex.sampleplugin.SystemIndexPlugin2.SYSTEM_INDEX_2;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SystemIndexPermissionEnabledTests {

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
                true,
                SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY,
                true
            )
        )
        .build();

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
}

