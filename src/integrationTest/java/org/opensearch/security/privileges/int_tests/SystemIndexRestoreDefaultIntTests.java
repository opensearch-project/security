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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.ELIGIBLE;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.SECURITY_ADMIN;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.cleanup;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.createIndicesAndSnapshot;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.restorePath;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;

/**
 * With {@code plugins.security.system_indices.restore.indices} left at its empty default, a security-admin cannot
 * restore any system index, for both the legacy and the V4 privilege evaluation.
 */
@RunWith(Parameterized.class)
public class SystemIndexRestoreDefaultIntTests {

    @ClassRule
    public static final ClusterConfig.ClusterInstances clusterInstances = new ClusterConfig.ClusterInstances(
        SystemIndexRestoreIntTests::defaultClusterBuilder
    );

    final LocalCluster cluster;

    @Test
    public void securityAdmin_cannotRestoreSystemIndexWhenNoneConfigured() {
        createIndicesAndSnapshot(cluster, "snap_default", ELIGIBLE);
        try (TestRestClient client = cluster.getRestClient(SECURITY_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(restorePath("snap_default"), json("indices", List.of(ELIGIBLE)));
            assertThat(response, isForbidden());
            assertThat(response.getBody(), containsString("[" + ELIGIBLE + "] are not eligible for restore."));
            assertThat(response.getBody(), not(containsString("Restorable system indices")));
        } finally {
            cleanup(cluster, "snap_default", ELIGIBLE);
        }
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();
        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            result.add(new Object[] { clusterConfig });
        }
        return result;
    }

    public SystemIndexRestoreDefaultIntTests(ClusterConfig clusterConfig) {
        this.cluster = clusterInstances.get(clusterConfig);
    }
}
