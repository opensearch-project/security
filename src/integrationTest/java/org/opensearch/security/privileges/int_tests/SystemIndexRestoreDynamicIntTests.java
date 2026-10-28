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
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.NOT_ELIGIBLE;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.NOT_REST_ADMIN;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.REST_ADMIN;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.cleanup;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.createIndicesAndSnapshot;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.resetRestorableIndices;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.restorableIndicesSetting;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.restorePath;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * With {@code plugins.security.system_indices.restore.dynamic.enabled} set to true, a REST admin can change
 * {@code plugins.security.system_indices.restore.indices} at runtime and other users still cannot, for both the legacy
 * and the V4 privilege evaluation.
 */
@RunWith(Parameterized.class)
public class SystemIndexRestoreDynamicIntTests {

    @ClassRule
    public static final ClusterConfig.ClusterInstances clusterInstances = new ClusterConfig.ClusterInstances(
        SystemIndexRestoreIntTests::dynamicClusterBuilder
    );

    final LocalCluster cluster;

    @Test
    public void restAdmin_canUpdateRestorableIndicesAtRuntime() {
        createIndicesAndSnapshot(cluster, "snap_dynamic", NOT_ELIGIBLE);
        try (TestRestClient client = cluster.getRestClient(REST_ADMIN)) {
            assertThat(client.post(restorePath("snap_dynamic"), json("indices", List.of(NOT_ELIGIBLE))), isForbidden());

            assertThat(client.putJson("_cluster/settings", restorableIndicesSetting("persistent", "[\"" + NOT_ELIGIBLE + "\"]")), isOk());

            assertThat(client.post(restorePath("snap_dynamic"), json("indices", List.of(NOT_ELIGIBLE))), isOk());
        } finally {
            resetRestorableIndices(cluster);
            cleanup(cluster, "snap_dynamic", NOT_ELIGIBLE);
        }
    }

    @Test
    public void notRestAdmin_cannotUpdateRestorableIndices() {
        try (TestRestClient client = cluster.getRestClient(NOT_REST_ADMIN)) {
            TestRestClient.HttpResponse response = client.putJson(
                "_cluster/settings",
                restorableIndicesSetting("persistent", "[\"" + NOT_ELIGIBLE + "\"]")
            );
            assertThat(response, isForbidden());
            assertThat(response.getBody(), containsString("does not have permission to update sensitive cluster settings"));
        } finally {
            resetRestorableIndices(cluster);
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

    public SystemIndexRestoreDynamicIntTests(ClusterConfig clusterConfig) {
        this.cluster = clusterInstances.get(clusterConfig);
    }
}
