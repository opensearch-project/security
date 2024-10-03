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
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.http.ExampleSystemIndexPlugin;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SystemIndexTests {

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(USER_ADMIN)
        .plugin(ExampleSystemIndexPlugin.class)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_SYSTEM_INDICES_ENABLED_KEY,
                true
            )
        )
        .build();

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
