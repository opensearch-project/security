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
import org.apache.http.HttpStatus;
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
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access to a resource shared with mixed access-levels. Some users are shared at read_only, others at full_access.
 * All tests are against USER_ADMIN's resource created during setup.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class MixedAccessTests {

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

    private void assertReadOnly(TestSecurityConfig.User user) throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, user));
        assertThat(response.getBody(), containsString("sample"));
        forbidden(() -> api.updateResource(resourceId, user, "sampleUpdateAdmin"));
        forbidden(() -> api.deleteResource(resourceId, user));
        forbidden(() -> api.shareResource(resourceId, user, user, SAMPLE_FULL_ACCESS));
        forbidden(() -> api.revokeResource(resourceId, user, user, SAMPLE_FULL_ACCESS));
    }

    private void assertFullAccess(TestSecurityConfig.User user) throws Exception {
        TestRestClient.HttpResponse response = ok(() -> api.getResource(resourceId, user));
        assertThat(response.getBody(), containsString("sample"));
        ok(() -> api.updateResource(resourceId, user, "sampleUpdateAdmin"));
        ok(() -> api.shareResource(resourceId, user, user, SAMPLE_FULL_ACCESS));
        ok(() -> api.revokeResource(resourceId, user, USER_ADMIN, SAMPLE_FULL_ACCESS));
        ok(() -> api.deleteResource(resourceId, user));
    }

    @Test
    public void multipleUsers_multipleLevels() throws Exception {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);
        // 1. share at read-only for full-access user and at full-access for limited-perms user
        ok(() -> api.shareResource(resourceId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_READ_ONLY));
        ok(() -> api.shareResource(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_FULL_ACCESS));

        // 2. check read-only access for full-access user
        assertReadOnly(FULL_ACCESS_USER);

        // 3. limited access user shares with full-access user at sampleAllAG
        ok(() -> api.shareResource(resourceId, LIMITED_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_FULL_ACCESS));

        // 4. full-access user now has full-access to admin's resource
        assertFullAccess(FULL_ACCESS_USER);
    }

    @Test
    public void multipleUsers_sameLevel() throws Exception {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);

        // 1. share with both users at read-only level
        ok(() -> api.shareResource(resourceId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_READ_ONLY));
        ok(() -> api.shareResource(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));

        // 2. assert both now have read-only access
        assertReadOnly(LIMITED_ACCESS_USER);
    }

    @Test
    public void sameUser_multipleLevels() throws Exception {
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);

        // 1. share with user at read-only level
        ok(() -> api.shareResource(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));

        // 2. assert user now has read-only access
        assertReadOnly(LIMITED_ACCESS_USER);

        // 3. share with user at full-access level
        ok(() -> api.shareResource(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_FULL_ACCESS));

        // 4. assert user now has full access
        assertFullAccess(LIMITED_ACCESS_USER);
    }

    private String getActualRoleName(TestSecurityConfig.User user, String baseRoleName) {
        return "user_" + user.getName() + "__" + baseRoleName;
    }

    @Test
    public void multipleRoles_multipleLevels() throws Exception {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);

        String fullAccessUserRole = getActualRoleName(FULL_ACCESS_USER, "shared_role");
        String limitedAccessUserRole = getActualRoleName(LIMITED_ACCESS_USER, "shared_role_limited_perms");

        // 1. share at read-only for shared_role and at full-access for shared_role_limited_perms
        ok(() -> api.shareResourceByRole(resourceId, USER_ADMIN, fullAccessUserRole, SAMPLE_READ_ONLY));
        ok(() -> api.shareResourceByRole(resourceId, USER_ADMIN, limitedAccessUserRole, SAMPLE_FULL_ACCESS));

        // 2. check read-only access for FULL_ACCESS_USER (has shared_role)
        assertReadOnly(FULL_ACCESS_USER);

        // 3. LIMITED_ACCESS_USER (has shared_role_limited_perms) shares with shared_role at sampleAllAG
        ok(() -> api.shareResourceByRole(resourceId, LIMITED_ACCESS_USER, fullAccessUserRole, SAMPLE_FULL_ACCESS));

        // 4. FULL_ACCESS_USER now has full-access to admin's resource
        assertFullAccess(FULL_ACCESS_USER);
    }

    @Test
    public void initialShare_multipleLevels() throws Exception {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);

        String shareWithPayload = """
            {
              "resource_id": "%s",
              "resource_type": "%s",
              "share_with": {
                "%s" : {
                    "users": ["%s"]
                },
                "%s" : {
                    "users": ["%s"]
                }
              }
            }
            """.formatted(
            resourceId,
            RESOURCE_TYPE,
            SAMPLE_FULL_ACCESS,
            LIMITED_ACCESS_USER.getName(),
            SAMPLE_READ_ONLY,
            FULL_ACCESS_USER.getName()
        );

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.putJson(SECURITY_SHARE_ENDPOINT, shareWithPayload);
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        // full-access user has read-only perm
        assertReadOnly(FULL_ACCESS_USER);

        // limited access user has full-access
        assertFullAccess(LIMITED_ACCESS_USER);

    }

}
