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

package org.opensearch.security.bwc;

import org.apache.http.entity.ContentType.APPLICATION_JSON;
import org.junit.Test;
import org.apache.http.entity.StringEntity;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.builder.SearchSourceBuilder;

public class SecurityBackwardsCompatibilityIT extends IntegrationTests {



    /**
     * Converting tests from https://github.com/opensearch-project/alerting/blob/92aa4bda9d2c42342f3e5bf9b28c54d96be8ec44/alerting/src/test/kotlin/org/opensearch/alerting/bwc/AlertingBackwardsCompatibilityIT.kt
     * 
     * Need to add validation of the plugin health to confirm that the migration has not caused an issue with the security plugin 
     */

    @Test
    public void testBackwardsCompatibility() {
        final String clusterType = ClusterType.parse(System.getProperty("tests.rest.bwcsuite"))
        final String clusterName = System.getProperty("tests.clustername")
        final String bwcRound = System.getProperty("tests.rest.bwcsuite_round");
    
        final String uri = getPluginUri(clusterType, clusterName, bwcRound);
        final Map<String, ?> responseMap = getAsMap(uri)["nodes"];
        for (Response response in responseMap.values()) {
            final String plugins = response["plugins"] as List<Map<String, ?>>;
            val pluginNames = plugins.map { plugin -> plugin["name"] }.toSet();
            switch (CLUSTER_TYPE) {
                case ClusterType.OLD:
                    assertTrue(pluginNames.contains("opendistro-security"));
                    // TODO: Verify cluster state is health
                    // TODO: Create security settings that need to be backward compatiable  
                    // TOOD: Verify settings have been applied
                    continue;
                case ClusterType.MIXED:
                    assertTrue(pluginNames.contains("opensearch-security"));
                    // TODO: Verify cluster state is health
                    // TODO: Small change to settings during migration (Optional?)
                    // TOOD: Verify settings have been applied
                    continue;
                ClusterType.UPGRADED -> {
                    assertTrue(pluginNames.contains("opensearch-security"))''
                    // TODO: Verify cluster state is health
                    // TODO: Small change to settings
                    // TOOD: Verify settings have been applied
                }
            }
            break
        }
    }

    private enum class ClusterType {
        OLD("old_cluster"),
        MIXED("mixed_cluster"),
        UPGRADED("upgraded_cluster");
        final String stringValue;
        private ClusterType(final String stringValue) {
            this.stringValue = stringValue;
        }

        static ClusterType parse(final String value) {
            for (ClusterType ct in ClusterType.values()) {
                if (ct.stringValue.equals(value)) {
                    return ct;
                }
            }
            throw new IllegalArugmentException("Unable to find value " + value);
        }
    }

    private String getPluginUri(final ClusterType ct, final String clusterName, final String round): String {
        switch (ct) {
            case ClusterType.OLD:
                return String.format("_nodes/%s-0/plugins", clusterName);

            case ClusterType.MIXED:
                final String roundName = round.equals("second") ? 1 : round.equals("third") ? 2 : 0;
                return String.format("_nodes/%s-%s/plugins", clusterName, roundName);

            case ClusterType.UPGRADED:
                return "_nodes/plugins";

            default:
                throw new IllegalArgumentException("Unsupported cluster type " + ct.)
        }
    }
}
