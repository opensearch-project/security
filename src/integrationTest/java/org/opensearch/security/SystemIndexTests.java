/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.util.FeatureFlags;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.plugin.SystemIndexPlugin1;
import org.opensearch.security.plugin.SystemIndexPlugin2;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.plugin.SystemIndexPlugin1.SYSTEM_INDEX_1;
import static org.opensearch.security.plugin.SystemIndexPlugin2.SYSTEM_INDEX_2;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SystemIndexTests {

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    // TODO Change this from SINGLENODE to default to test with multiple nodes
    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(USER_ADMIN)
        .plugin(List.of(SystemIndexPlugin1.class, SystemIndexPlugin2.class))
        .nodeSettings(
            Map.of(
                FeatureFlags.IDENTITY,
                true,
                SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY,
                true,
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true
            )
        )
        .build();

    @Before
    public void wipeAllIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(".system-index1");
            client.delete(".system-index2");
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

            // regular use cannot create system index when system index protection is enforced
            HttpResponse response3 = client.put(".system-index1");

            assertThat(response3.getStatusCode(), equalTo(RestStatus.FORBIDDEN.getStatus()));
        }
    }

    @Test
    public void testPluginShouldBeAbleToIndexDocumentIntoItsSystemIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
            assertThat(response.getBody(), containsString(SystemIndexPlugin1.class.getCanonicalName()));
        }
    }

    @Test
    public void testPluginShouldNotBeAbleToIndexDocumentIntoSystemIndexRegisteredByOtherPlugin() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-index/" + SYSTEM_INDEX_2);

            assertThat(response.getStatusCode(), equalTo(RestStatus.FORBIDDEN.getStatus()));
            assertThat(
                response.getBody(),
                containsString("no permissions for [indices:admin/create] and User [name=org.opensearch.security.plugin.SystemIndexPlugin1")
            );
        }
    }

    @Test
    public void testPluginShouldNotBeAbleToRunClusterActions() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("try-cluster-health/plugin");

            assertThat(response.getStatusCode(), equalTo(RestStatus.FORBIDDEN.getStatus()));
            assertThat(
                response.getBody(),
                containsString(
                    "no permissions for [cluster:monitor/health] and User [name=org.opensearch.security.plugin.SystemIndexPlugin1"
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
    public void testPluginShouldBeAbleToBulkIndexDocumentIntoItsSystemIndex() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.put("try-create-and-bulk-index/" + SYSTEM_INDEX_1);

            assertThat(response.getStatusCode(), equalTo(RestStatus.OK.getStatus()));
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
                    "no permissions for [indices:data/write/bulk[s]] and User [name=org.opensearch.security.plugin.SystemIndexPlugin1"
                )
            );
        }
    }
}
