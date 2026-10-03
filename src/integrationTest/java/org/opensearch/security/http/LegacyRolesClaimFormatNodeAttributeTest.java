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

package org.opensearch.security.http;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.authtoken.jwt.LegacyRolesClaimFormat;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Every node that runs this plugin advertises the internal node attribute from which the other nodes tell that
 * it reads AES-GCM on-behalf-of tokens. Checked on real nodes, so it covers what the unit tests cannot: that the
 * plugin's additional settings carry the attribute and that the core turns it into a node attribute in the
 * cluster state.
 */
@RunWith(org.junit.runners.JUnit4.class)
public class LegacyRolesClaimFormatNodeAttributeTest {

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .build();

    @Test
    public void everyNodeAdvertisesTheInternalAttribute() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // the cluster state's view of the nodes, which is what the gates in LegacyRolesClaimFormat read
            final HttpResponse response = client.get("_cluster/state/nodes");
            response.assertStatusCode(200);

            final JsonNode nodes = response.bodyAsJsonNode().get("nodes");
            assertThat(response.getBody(), nodes.size(), is(cluster.nodes().size()));
            for (final JsonNode node : nodes) {
                assertThat(
                    node.get("name").asText(),
                    node.path("attributes").path(LegacyRolesClaimFormat.INTERNAL_AES_GCM_NODE_ATTRIBUTE).asString(),
                    is("true")
                );
            }
        }
    }
}
