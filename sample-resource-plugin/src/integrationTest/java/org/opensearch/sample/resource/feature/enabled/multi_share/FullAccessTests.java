/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled.multi_share;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access when shared with full-access (sampleAllAG action-group).
 * All tests are against USER_ADMIN's resource created during setup.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FullAccessTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String resourceId;

    @Before
    public void setup() {
        resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId); // wait until sharing entry is created
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    private void assertNoAccessBeforeSharing(TestSecurityConfig.User user) throws Exception {
        forbidden(() -> api.getResource(resourceId, user));
        forbidden(() -> api.updateResource(resourceId, user, "sampleUpdateAdmin"));
        forbidden(() -> api.deleteResource(resourceId, user));

        forbidden(() -> api.shareResource(resourceId, user, user, SAMPLE_FULL_ACCESS));
        forbidden(() -> api.revokeResource(resourceId, user, user, SAMPLE_FULL_ACCESS));
    }

    private void assertRUDAccess(TestSecurityConfig.User user) throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, user));
        assertThat(response.getBody(), containsString("sample"));
        ok(() -> api.updateResource(resourceId, user, "sampleUpdateAdmin"));
        ok(() -> api.deleteResource(resourceId, user));
    }

    // check that target cannot access before sharing and after revoking
    // while resource is shared, they can access it and share it someone else
    private void assertSharingAccess(TestSecurityConfig.User user, TestSecurityConfig.User target) throws Exception {
        forbidden(() -> api.getResource(resourceId, target));
        ok(() -> api.shareResource(resourceId, user, target, SAMPLE_FULL_ACCESS));

        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, target));
        assertThat(response.getBody(), containsString("sample"));
        ok(() -> api.shareResource(resourceId, target, new TestSecurityConfig.User("test"), SAMPLE_FULL_ACCESS));

        ok(() -> api.revokeResource(resourceId, user, target, SAMPLE_FULL_ACCESS));
        forbidden(() -> api.getResource(resourceId, target));
    }

    @Test
    public void fullAccessUser_canCRUD() throws Exception {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        // share at sample_full_access level
        ok(() -> api.shareResource(resourceId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_FULL_ACCESS));

        // can share admin's resource with others since full access was granted
        assertSharingAccess(FULL_ACCESS_USER, LIMITED_ACCESS_USER);

        assertRUDAccess(FULL_ACCESS_USER);
    }

    @Test
    public void limitedAccessUser_canCRUD() throws Exception {
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);
        // share at sample_full_access level
        ok(() -> api.shareResource(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_FULL_ACCESS));

        assertSharingAccess(LIMITED_ACCESS_USER, FULL_ACCESS_USER);

        assertRUDAccess(LIMITED_ACCESS_USER);
    }

    @Test
    public void noAccessUser_canCRUD() throws Exception {
        assertNoAccessBeforeSharing(NO_ACCESS_USER);
        // share at sample_full_access level
        ok(() -> api.shareResource(resourceId, USER_ADMIN, NO_ACCESS_USER, SAMPLE_FULL_ACCESS));

        assertSharingAccess(NO_ACCESS_USER, LIMITED_ACCESS_USER);

        assertRUDAccess(NO_ACCESS_USER);
    }
}
