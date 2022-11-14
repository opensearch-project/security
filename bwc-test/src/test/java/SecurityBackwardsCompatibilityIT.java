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

import org.junit.Assume;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.client.Response;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestStatus;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import org.opensearch.Version;
import com.google.common.collect.ImmutableMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;

public class SecurityBackwardsCompatibilityIT extends OpenSearchRestTestCase {

    private ClusterType CLUSTER_TYPE;
    private String CLUSTER_NAME;

    @Before
    private void testSetup() {
        final String bwcsuiteString = System.getProperty("tests.rest.bwcsuite");
        Assume.assumeTrue("Test cannot be run outside the BWC gradle task 'bwcTestSuite' or its dependent tasks", bwcsuiteString != null);
        CLUSTER_TYPE = ClusterType.parse(bwcsuiteString);
        CLUSTER_NAME = System.getProperty("tests.clustername");
    }

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

    public void testBasicBackwardsCompatibility() throws Exception {
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
            Set<String> pluginNames = plugins.stream().map(map -> (String) map.get("name")).collect(Collectors.toSet());

            final Version minNodeVersion = this.minimumNodeVersion();

            if (minNodeVersion.major <= 1) {
                assertThat(pluginNames, hasItem("opensearch_security"));
            } else {
                assertThat(pluginNames, hasItem("opensearch-security"));
            }

        }
    }
}
