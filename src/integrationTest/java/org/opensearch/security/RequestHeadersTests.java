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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

public class RequestHeadersTests {

    public static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0).httpAuthenticatorWithChallenge("basic").backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_DOMAIN)
        .users(USER_ADMIN)
        .nodeSettings(Map.of(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName())))
        .build();

    @Test
    public void testRequestHeadersArePassedThrough() throws IOException, InterruptedException {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.put("test-index");

            XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.startObject();
            builder.field("field1", "foo");
            builder.endObject();

            HttpResponse indexDocResponse = client.putJson(
                "test-index/_doc/2",
                builder.toString(),
                new BasicHeader(Task.X_OPAQUE_ID, "2"),
                new BasicHeader(Task.X_REQUEST_ID, "a1b2c3d4e5f67890abcdef1234567890")
            );

            assertThat(indexDocResponse.getStatusCode(), equalTo(RestStatus.CREATED.getStatus()));
            assertThat(indexDocResponse.getHeader(Task.X_OPAQUE_ID).getValue(), equalTo("2"));
            assertThat(indexDocResponse.getHeader(Task.X_REQUEST_ID).getValue(), equalTo("a1b2c3d4e5f67890abcdef1234567890"));
        }
    }
}
