/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.sample.secure;

import org.junit.ClassRule;

import org.opensearch.test.framework.cluster.LocalCluster;

/**
 * Runs {@link PluginPermissionsActionGroupTests} on a cluster that starts with the legacy privileges evaluator.
 */
public class LegacyPluginPermissionsActionGroupTests extends PluginPermissionsActionGroupTests {

    /**
     * The cluster under test.
     */
    @ClassRule
    public static final LocalCluster CLUSTER = clusterBuilder("legacy").build();

    /**
     * Creates the tests for {@link #CLUSTER}.
     */
    public LegacyPluginPermissionsActionGroupTests() {
        super(CLUSTER, "legacy");
    }
}
