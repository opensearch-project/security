/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security;

import org.awaitility.Awaitility;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

public class SecuritySettingsTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .build();

    @Test
    public void testTtlInMinCanBeUpdatedDynamically() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse updateResponse = client.putJson("_cluster/settings", """
                    {
                        "persistent": { },
                        "transient": {
                            "plugins.security.cache.ttl_minutes": "1440"
                        }
                    }
                """);

            updateResponse.assertStatusCode(200);
            Awaitility.await().untilAsserted(() -> {
                TestRestClient.HttpResponse response = client.get("_plugins/_security/health");
                assertThat(response.getBody(), containsString("\"" + ConfigConstants.SECURITY_CACHE_TTL_MINUTES + "\":1440"));
            });
        }
    }
}
