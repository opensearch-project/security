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
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.ELIGIBLE;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.NOT_ELIGIBLE;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.REST_ADMIN;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.cleanup;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.createIndicesAndSnapshot;
import static org.opensearch.security.privileges.int_tests.SystemIndexRestoreIntTests.restorePath;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

/**
 * With {@code plugins.security.system_indices.restore.indices} left at its default, a REST admin can restore the system
 * indices in the default list and no others, for both the legacy and the V4 privilege evaluation.
 */
@RunWith(Parameterized.class)
public class SystemIndexRestoreDefaultIntTests {

    @ClassRule
    public static final ClusterConfig.ClusterInstances clusterInstances = new ClusterConfig.ClusterInstances(
        SystemIndexRestoreIntTests::defaultClusterBuilder
    );

    final LocalCluster cluster;

    @Test
    public void restAdmin_restoresSystemIndicesInDefaultList() {
        createIndicesAndSnapshot(cluster, "snap_default", ELIGIBLE);
        try (TestRestClient client = cluster.getRestClient(REST_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(restorePath("snap_default"), json("indices", List.of(ELIGIBLE)));
            assertThat(response, isOk());
        } finally {
            cleanup(cluster, "snap_default", ELIGIBLE);
        }
    }

    @Test
    public void restAdmin_cannotRestoreSystemIndexOutsideDefaultList() {
        createIndicesAndSnapshot(cluster, "snap_not_in_default", NOT_ELIGIBLE);
        try (TestRestClient client = cluster.getRestClient(REST_ADMIN)) {
            TestRestClient.HttpResponse response = client.post(restorePath("snap_not_in_default"), json("indices", List.of(NOT_ELIGIBLE)));
            assertThat(response, isForbidden());
            assertThat(response.getBody(), containsString("[" + NOT_ELIGIBLE + "] are not eligible for restore."));
            assertThat(response.getBody(), containsString("Restorable system indices: [" + ELIGIBLE));
        } finally {
            cleanup(cluster, "snap_not_in_default", NOT_ELIGIBLE);
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
