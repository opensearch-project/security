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
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access to a publicly shared resource at different access-levels.
 * All tests are against USER_ADMIN's resource created during setup.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PubliclySharedDocTests {

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

    private void assertReadOnly() throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));
        forbidden(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "sampleUpdateAdmin"));
        forbidden(() -> api.deleteResource(resourceId, FULL_ACCESS_USER));

        forbidden(() -> api.shareResource(resourceId, FULL_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_FULL_ACCESS));
        forbidden(() -> api.revokeResource(resourceId, FULL_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_FULL_ACCESS));
    }

    private void assertFullAccess() throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, LIMITED_ACCESS_USER));
        assertThat(response.getBody(), containsString("sample"));
        ok(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "sampleUpdateAdmin"));
        ok(() -> api.shareResource(resourceId, LIMITED_ACCESS_USER, TestUtils.LIMITED_ACCESS_USER, SAMPLE_FULL_ACCESS));
        ok(() -> api.revokeResource(resourceId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_FULL_ACCESS));
        ok(() -> api.deleteResource(resourceId, LIMITED_ACCESS_USER));
    }

    @Test
    public void readOnly() throws Exception {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        // 1. share at read-only for full-access user and at full-access for limited perms user
        ok(() -> api.shareResource(resourceId, USER_ADMIN, new TestSecurityConfig.User("*"), SAMPLE_READ_ONLY));

        // 2. check read-only access for full-access user
        assertReadOnly();
    }

    @Test
    public void fullAccess() throws Exception {
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);
        // 1. share at read-only for full-access user and at full-access for limited perms user
        ok(() -> api.shareResource(resourceId, USER_ADMIN, new TestSecurityConfig.User("*"), SAMPLE_FULL_ACCESS));

        // 2. check read-only access for full-access user
        assertFullAccess();
    }

}
