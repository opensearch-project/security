/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resourcegroup;

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
import static org.opensearch.sample.resource.TestUtils.SAMPLE_GROUP_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_GROUP_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access to a resource shared with mixed access-levels. Some users are shared at read_only, others at full_access.
 * All tests are against USER_ADMIN's resource created during setup.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceHierarchyTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String resourceGroupId;
    private String resourceId;

    @Before
    public void setup() {
        resourceGroupId = api.createSampleResourceGroupAs(USER_ADMIN);
        api.awaitSharingEntry(resourceGroupId); // wait until sharing entry is created
        resourceId = api.createSampleResourceWithGroupAs(USER_ADMIN, resourceGroupId);
        api.awaitSharingEntry(resourceId); // wait until sharing entry is created
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    private void assertNoAccessBeforeSharing(TestSecurityConfig.User user) throws Exception {
        forbidden(() -> api.getResourceGroup(resourceGroupId, user));
        forbidden(() -> api.updateResourceGroup(resourceGroupId, user, "sampleUpdateAdmin"));
        forbidden(() -> api.deleteResourceGroup(resourceGroupId, user));

        forbidden(() -> api.shareResourceGroup(resourceGroupId, user, user, SAMPLE_GROUP_FULL_ACCESS));
        forbidden(() -> api.revokeResourceGroup(resourceGroupId, user, user, SAMPLE_GROUP_FULL_ACCESS));
    }

    @Test
    public void testShouldHaveAccessToResourceWithGroupLevelAccess() throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, USER_ADMIN));
        assertThat(response.getBody(), containsString("sample"));

        forbidden(() -> api.getResourceGroup(resourceGroupId, FULL_ACCESS_USER));
        forbidden(() -> api.getResource(resourceGroupId, FULL_ACCESS_USER));

        // 1. share at read-only for full-access user and at full-access for limited-perms user
        ok(() -> api.shareResourceGroup(resourceGroupId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_GROUP_READ_ONLY));

        ok(() -> api.getResourceGroup(resourceGroupId, FULL_ACCESS_USER));
        ok(() -> api.getResource(resourceGroupId, FULL_ACCESS_USER));
    }

}
