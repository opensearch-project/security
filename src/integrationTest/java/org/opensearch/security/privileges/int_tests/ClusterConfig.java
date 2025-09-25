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

import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

import org.opensearch.test.framework.cluster.LocalCluster;

/**
 * This is one of the test parameter dimensions used by the *Authorization*IntTests test suites.
 * The test suites run on different cluster configurations; the possible cluster configurations are defined here.
 */
public enum ClusterConfig {
    LEGACY_PRIVILEGES_EVALUATION(
        "legacy",
        c -> c.doNotFailOnForbidden(true).nodeSettings(Map.of("plugins.security.system_indices.enabled", true)),
        true,
        false,
        false
    ),
    LEGACY_PRIVILEGES_EVALUATION_SYSTEM_INDEX_PERMISSION(
        "legacy_system_index_perm",
        c -> c.doNotFailOnForbidden(true)
            .nodeSettings(
                Map.of("plugins.security.system_indices.enabled", true, "plugins.security.system_indices.permission.enabled", true)
            ),
        true,
        true,
        false
    );

    final String name;
    final Function<LocalCluster.Builder, LocalCluster.Builder> clusterConfiguration;
    final boolean legacyPrivilegeEvaluation;
    final boolean systemIndexPrivilegeEnabled;
    final boolean allowsEmptyResultSets;

    private LocalCluster cluster;

    ClusterConfig(
        String name,
        Function<LocalCluster.Builder, LocalCluster.Builder> clusterConfiguration,
        boolean legacyPrivilegeEvaluation,
        boolean systemIndexPrivilegeEnabled,
        boolean allowsEmptyResultSets
    ) {
        this.name = name;
        this.clusterConfiguration = clusterConfiguration;
        this.legacyPrivilegeEvaluation = legacyPrivilegeEvaluation;
        this.systemIndexPrivilegeEnabled = systemIndexPrivilegeEnabled;
        this.allowsEmptyResultSets = allowsEmptyResultSets;
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
            } catch (Exception e) {}
            cluster = null;
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
