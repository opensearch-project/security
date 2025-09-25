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

import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.sampleAllAG;
import static org.opensearch.sample.resource.TestUtils.sampleReadOnlyAG;
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

    private void assertNoAccessBeforeSharing(TestSecurityConfig.User user) {
        api.assertApiGet(resourceId, user, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiUpdate(resourceId, user, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

        api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
    }

    private void assertReadOnly(TestSecurityConfig.User user) {
        api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, user, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

        api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
    }

    private void assertFullAccess(TestSecurityConfig.User user) {
        api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, user, "sampleUpdateAdmin", HttpStatus.SC_OK);
        api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_OK);
        api.assertApiRevoke(resourceId, user, USER_ADMIN, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId);
        api.assertApiDelete(resourceId, user, HttpStatus.SC_OK);
    }

    @Test
    public void multipleUsers_multipleLevels() {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);
        // 1. share at read-only for full-access user and at full-access for limited-perms user
        api.assertApiShare(resourceId, USER_ADMIN, FULL_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
        api.assertApiShare(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId, FULL_ACCESS_USER.getName());
        api.awaitSharingEntry(resourceId, LIMITED_ACCESS_USER.getName());

        // 2. check read-only access for full-access user
        assertReadOnly(FULL_ACCESS_USER);

        // 3. limited access user shares with full-access user at sampleAllAG
        api.assertApiShare(resourceId, LIMITED_ACCESS_USER, FULL_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId, FULL_ACCESS_USER.getName());

        // 4. full-access user now has full-access to admin's resource
        assertFullAccess(FULL_ACCESS_USER);
    }

    @Test
    public void multipleUsers_sameLevel() {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);

        // 1. share with both users at read-only level
        api.assertApiShare(resourceId, USER_ADMIN, FULL_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
        api.assertApiShare(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId, sampleReadOnlyAG.name());

        // 2. assert both now have read-only access
        assertReadOnly(LIMITED_ACCESS_USER);
    }

    @Test
    public void sameUser_multipleLevels() {
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);

        // 1. share with user at read-only level
        api.assertApiShare(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId, LIMITED_ACCESS_USER.getName());

        // 2. assert user now has read-only access
        assertReadOnly(LIMITED_ACCESS_USER);

        // 3. share with user at full-access level
        api.assertApiShare(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId, sampleAllAG.name());

        // 4. assert user now has full access
        assertFullAccess(LIMITED_ACCESS_USER);
    }

    private String getActualRoleName(TestSecurityConfig.User user, String baseRoleName) {
        return "user_" + user.getName() + "__" + baseRoleName;
    }

    @Test
    public void multipleRoles_multipleLevels() {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);

        String fullAccessUserRole = getActualRoleName(FULL_ACCESS_USER, "shared_role");
        String limitedAccessUserRole = getActualRoleName(LIMITED_ACCESS_USER, "shared_role_limited_perms");

        // 1. share at read-only for shared_role and at full-access for shared_role_limited_perms
        api.assertApiShareByRole(resourceId, USER_ADMIN, fullAccessUserRole, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
        api.assertApiShareByRole(resourceId, USER_ADMIN, limitedAccessUserRole, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId, fullAccessUserRole);
        api.awaitSharingEntry(resourceId, limitedAccessUserRole);

        // 2. check read-only access for FULL_ACCESS_USER (has shared_role)
        assertReadOnly(FULL_ACCESS_USER);

        // 3. LIMITED_ACCESS_USER (has shared_role_limited_perms) shares with shared_role at sampleAllAG
        api.assertApiShareByRole(resourceId, LIMITED_ACCESS_USER, fullAccessUserRole, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(resourceId, fullAccessUserRole);

        // 4. FULL_ACCESS_USER now has full-access to admin's resource
        assertFullAccess(FULL_ACCESS_USER);
    }

}
