/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import java.util.List;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Tests a request that names several resources at once. Such a request reports its ids through
 * {@code MultiResourceRequest}, and the evaluator allows it only if every id is accessible to the user.
 * <p>
 * The requesting user holds no cluster or index permission at all, so an allowed request can only have been allowed by
 * resource-level evaluation, and a denied one cannot be confused with a missing role.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class MultiIdRequestAccessTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    private String resourceOne;
    private String resourceTwo;

    @Before
    public void setup() {
        resourceOne = api.createSampleResourceAs(USER_ADMIN);
        resourceTwo = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceOne);
        api.awaitSharingEntry(resourceTwo);
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void everyIdShared_isAllowed() throws Exception {
        ok(() -> api.shareResource(resourceOne, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));
        ok(() -> api.shareResource(resourceTwo, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));

        TestRestClient.HttpResponse response = ok(() -> api.multiGetResources(List.of(resourceOne, resourceTwo), NO_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));
    }

    @Test
    public void oneIdNotShared_isForbidden() throws Exception {
        ok(() -> api.shareResource(resourceOne, USER_ADMIN, NO_ACCESS_USER, SAMPLE_READ_ONLY));

        // the shared id on its own is allowed, so the denial below is about the second id and not about the request shape
        ok(() -> api.multiGetResources(List.of(resourceOne), NO_ACCESS_USER));
        forbidden(() -> api.multiGetResources(List.of(resourceOne, resourceTwo), NO_ACCESS_USER));
    }

    @Test
    public void noIdShared_isForbidden() throws Exception {
        forbidden(() -> api.multiGetResources(List.of(resourceOne, resourceTwo), NO_ACCESS_USER));
    }

    @Test
    public void owner_isAllowedForEveryId() throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.multiGetResources(List.of(resourceOne, resourceTwo), USER_ADMIN));
        assertThat(response.getBody(), containsString("sample"));
    }
}
