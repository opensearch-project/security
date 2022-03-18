/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.bwc;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestStatus;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import com.google.common.collect.ImmutableMap;

public class SecurityBackwardsCompatibilityIT extends OpenSearchRestTestCase {

    private static final ClusterType CLUSTER_TYPE = ClusterType.parse(System.getProperty("tests.rest.bwcsuite"));
    private static final String CLUSTER_NAME = System.getProperty("tests.clustername");

    @Override
    protected final boolean preserveIndicesUponCompletion() {
        return true;
    }

    @Override
    protected final boolean preserveReposUponCompletion() {
        return true;
    }

    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    @Override
    protected final Settings restClientSettings() {
        return Settings
                .builder()
                .put(super.restClientSettings())
                // increase the timeout here to 90 seconds to handle long waits for a green
                // cluster health. the waits for green need to be longer than a minute to
                // account for delayed shards
                .put(OpenSearchRestTestCase.CLIENT_SOCKET_TIMEOUT, "90s")
                .build();
    }

    public void testPluginUpgradeInAMixedCluster() throws Exception {
        assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-0/plugins");
    }

    public void testPluginUpgradeInAnUpgradedCluster() throws Exception {
        assertPluginUpgrade("_nodes/plugins");
    }

    public void testPluginUpgradeInARollingUpgradedCluster() throws Exception {
        String round = System.getProperty("tests.rest.bwcsuite_round");
        if (round.equals("first") || round.equals("old")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-0/plugins");
        } else if (round.equals("second")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-1/plugins");
        } else if (round.equals("third")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-2/plugins");
        }
    }

    private enum ClusterType {
        OLD,
        MIXED,
        UPGRADED;

        public static ClusterType parse(String value) {
            switch (value) {
                case "old_cluster":
                    return OLD;
                case "mixed_cluster":
                    return MIXED;
                case "upgraded_cluster":
                    return UPGRADED;
                default:
                    throw new AssertionError("unknown cluster type: " + value);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void assertPluginUpgrade(String uri) throws Exception {
        Map<String, Map<String, Object>> responseMap = (Map<String, Map<String, Object>>) getAsMap(uri).get("nodes");
        for (Map<String, Object> response : responseMap.values()) {
            List<Map<String, Object>> plugins = (List<Map<String, Object>>) response.get("plugins");
            Set<Object> pluginNames = plugins.stream().map(map -> map.get("name")).collect(Collectors.toSet());
            switch (CLUSTER_TYPE) {
                case OLD:
                    Assert.assertTrue(pluginNames.contains("opendistro_security"));
                    break;
                case MIXED:
                    Assert.assertTrue(pluginNames.contains("opensearch-security"));
                    break;
                case UPGRADED:
                    Assert.assertTrue(pluginNames.contains("opendistro_security"));
                    break;
            }
            break;
        }
    }
}
