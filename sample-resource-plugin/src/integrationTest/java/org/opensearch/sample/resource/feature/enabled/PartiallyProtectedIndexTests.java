/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import java.time.Duration;
import java.util.List;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GROUP_SEARCH_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Tests an index that hosts a protected type and an unprotected one. Resource sharing governs only the protected type:
 * documents of the unprotected type are searched as they would be with resource sharing disabled.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PartiallyProtectedIndexTests {

    // sample-resource-group shares the index with sample-resource but is not protected here
    @ClassRule
    public static LocalCluster cluster = newCluster(true, true, List.of(RESOURCE_TYPE));

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void testUnprotectedTypeOnAProtectedIndexStaysSearchable() {
        String groupId = api.createSampleResourceGroupAs(FULL_ACCESS_USER);

        awaitGroupSearchReturns(groupId);
    }

    @Test
    public void testProtectedTypeOnTheSameIndexStaysFiltered() {
        // The search runs over the whole index, so it would return this resource too if the exemption were too wide
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);
        String groupId = api.createSampleResourceGroupAs(FULL_ACCESS_USER);

        assertThat(awaitGroupSearchReturns(groupId), not(containsString(resourceId)));
    }

    /** Polls group search as {@code FULL_ACCESS_USER} until it returns {@code groupId}, and returns that response body. */
    private String awaitGroupSearchReturns(String groupId) {
        try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
            return Awaitility.await("group " + groupId + " is returned by group search")
                .atMost(Duration.ofSeconds(15))
                .pollInterval(Duration.ofMillis(500))
                .until(() -> client.get(SAMPLE_RESOURCE_GROUP_SEARCH_ENDPOINT).getBody(), body -> body.contains(groupId));
        }
    }
}
