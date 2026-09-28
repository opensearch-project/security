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
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
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

    @Test
    public void testShouldHaveAccessToResourceWithGroupLevelAccess() throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, USER_ADMIN));
        assertThat(response.getBody(), containsString("sample"));

        forbidden(() -> api.getResourceGroup(resourceGroupId, FULL_ACCESS_USER));
        forbidden(() -> api.getResource(resourceGroupId, FULL_ACCESS_USER));

        ok(() -> api.shareResourceGroup(resourceGroupId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_GROUP_READ_ONLY));

        ok(() -> api.getResourceGroup(resourceGroupId, FULL_ACCESS_USER));
        ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));
    }

    @Test
    public void testGroupReadOnlyShouldNotGrantWriteOnChild() throws Exception {
        ok(() -> api.shareResourceGroup(resourceGroupId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_GROUP_READ_ONLY));

        // read is allowed via parent
        ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));

        // write/delete on child should still be forbidden — read_only only maps to get actions
        forbidden(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "shouldFail"));
        forbidden(() -> api.deleteResource(resourceId, FULL_ACCESS_USER));
    }

    @Test
    public void testRevokingGroupAccessRemovesChildAccess() throws Exception {
        ok(() -> api.shareResourceGroup(resourceGroupId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_GROUP_READ_ONLY));

        ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));

        ok(() -> api.revokeResourceGroup(resourceGroupId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_GROUP_READ_ONLY));

        forbidden(() -> api.getResourceGroup(resourceGroupId, FULL_ACCESS_USER));
        forbidden(() -> api.getResource(resourceId, FULL_ACCESS_USER));
    }

    @Test
    public void testDirectChildShareGrantsAccessWithoutGroupShare() throws Exception {
        // group is not shared with FULL_ACCESS_USER at all
        forbidden(() -> api.getResourceGroup(resourceGroupId, FULL_ACCESS_USER));
        forbidden(() -> api.getResource(resourceId, FULL_ACCESS_USER));

        // share the child directly at full_access
        ok(() -> api.shareResource(resourceId, USER_ADMIN, FULL_ACCESS_USER, TestUtils.SAMPLE_FULL_ACCESS));

        // child is now accessible
        ok(() -> api.getResource(resourceId, FULL_ACCESS_USER));
        ok(() -> api.updateResource(resourceId, FULL_ACCESS_USER, "directShareUpdate"));

        // group itself remains inaccessible
        forbidden(() -> api.getResourceGroup(resourceGroupId, FULL_ACCESS_USER));
    }

}
