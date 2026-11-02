/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.assertSearchResponse;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Checks that search and the resource-list API agree with the permission check across a share and a revoke.
 * <p>
 * The permission check reads the sharing record, while search and list read {@code all_shared_principals}, which is
 * derived from it and written separately. The subject holds the read actions through a role but is not the owner, so
 * only resource sharing decides what comes back.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class VisibilityConsistencyTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    // Every sample resource has the same name, so rename it to one this test can find in a response body
    private static final String RESOURCE_NAME = "visibility_consistency_subject";

    private String resourceId;

    @Before
    public void setup() throws Exception {
        resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);
        ok(() -> api.updateResource(resourceId, USER_ADMIN, RESOURCE_NAME));
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void shareThenRevoke_keepsSearchAndListInStepWithTheRecord() throws Exception {
        // Before sharing: not reachable by any path
        assertThat(ok(() -> api.listResources(LIMITED_ACCESS_USER)).getBody(), not(containsString(RESOURCE_NAME)));
        assertSearchResponse(ok(() -> api.searchResources(LIMITED_ACCESS_USER)), 0, null);

        ok(() -> api.shareResource(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));

        // Shared: the point check allows it, so both read paths must show it
        assertThat(ok(() -> api.getResource(resourceId, LIMITED_ACCESS_USER)).getBody(), containsString(RESOURCE_NAME));
        assertThat(ok(() -> api.listResources(LIMITED_ACCESS_USER)).getBody(), containsString(RESOURCE_NAME));
        assertSearchResponse(ok(() -> api.searchResources(LIMITED_ACCESS_USER)), 1, RESOURCE_NAME);

        ok(() -> api.revokeResource(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));

        // Revoked: neither read path may still return it, since a stale field here widens access
        assertThat(ok(() -> api.listResources(LIMITED_ACCESS_USER)).getBody(), not(containsString(RESOURCE_NAME)));
        assertSearchResponse(ok(() -> api.searchResources(LIMITED_ACCESS_USER)), 0, null);
    }
}
