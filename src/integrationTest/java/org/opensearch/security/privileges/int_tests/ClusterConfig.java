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

package org.opensearch.security.privileges.int_tests;

import org.opensearch.test.framework.cluster.LocalCluster;

import java.util.function.Function;
import java.util.function.Supplier;

public enum ClusterConfig {
    LEGACY_PRIVILEGES_EVALUATION("legacy", c -> c.doNotFailOnForbidden(true)),
    NEXT_GEN_PRIVILEGES_EVALUATION("next_gen", c -> c.privilegesEvaluationType("next_gen"));

    final String name;
    final Function<LocalCluster.Builder, LocalCluster.Builder> clusterConfiguration;
    private LocalCluster cluster;

    ClusterConfig(String name, Function<LocalCluster.Builder, LocalCluster.Builder> clusterConfiguration) {
        this.name = name;
        this.clusterConfiguration = clusterConfiguration;
    }

    LocalCluster cluster(Supplier<LocalCluster.Builder> clusterBuilder) {
        if (cluster == null) {
            cluster = this.clusterConfiguration.apply(clusterBuilder.get()).build();
            cluster.before();
        }
        return cluster;
    }

    void shutdown() {
        if (cluster != null) {
            try {
                cluster.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            cluster = null;
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
