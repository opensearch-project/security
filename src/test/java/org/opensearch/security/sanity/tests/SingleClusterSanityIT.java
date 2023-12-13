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

package org.opensearch.security.sanity.tests;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.junit.Test;

import org.opensearch.client.Request;
import org.opensearch.client.Response;

import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

@SuppressWarnings("unchecked")
public class SingleClusterSanityIT extends SecurityRestTestCase {

    private static final String SECURITY_PLUGIN_NAME = "opensearch-security";

    @Test
    public void testSecurityPluginInstallation() throws Exception {
        verifyPluginInstallationOnAllNodes();
    }

    @Test
    public void testAdminCredentials_validAdminPassword_shouldSucceed() throws Exception {
        Response response = client().performRequest(new Request("GET", ""));
        MatcherAssert.assertThat(response.getStatusLine().getStatusCode(), is(equalTo(200)));
        MatcherAssert.assertThat(response.getStatusLine().getReasonPhrase(), is(equalTo("OK")));
    }

    private void verifyPluginInstallationOnAllNodes() throws Exception {

        Map<String, Map<String, Object>> nodesInCluster = (Map<String, Map<String, Object>>) getAsMapByAdmin("_nodes").get("nodes");

        for (Map<String, Object> node : nodesInCluster.values()) {

            List<Map<String, Object>> plugins = (List<Map<String, Object>>) node.get("plugins");
            Set<Object> pluginNames = plugins.stream().map(map -> map.get("name")).collect(Collectors.toSet());

            MatcherAssert.assertThat(pluginNames, hasItem(SECURITY_PLUGIN_NAME));
        }
        MatcherAssert.assertThat(nodesInCluster, is(not(anEmptyMap())));
    }
}
