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
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.sampleAllAG;
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
        api.awaitSharingEntry(); // wait until sharing entry is created
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

    private void assertRUDAccess(TestSecurityConfig.User user) {
        api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, user, "sampleUpdateAdmin", HttpStatus.SC_OK);
        api.assertApiDelete(resourceId, user, HttpStatus.SC_OK);
    }

    // check that target cannot access before sharing and after revoking
    // while resource is shared, they can access it and share it someone else
    private void assertSharingAccess(TestSecurityConfig.User user, TestSecurityConfig.User target) {
        api.assertApiGet(resourceId, target, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiShare(resourceId, user, target, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(target.getName());

        api.assertApiGet(resourceId, target, HttpStatus.SC_OK, "sample");
        api.assertApiShare(resourceId, target, new TestSecurityConfig.User("test"), sampleAllAG.name(), HttpStatus.SC_OK);

        api.assertApiRevoke(resourceId, user, target, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry();
        api.assertApiGet(resourceId, target, HttpStatus.SC_FORBIDDEN, "");
    }

    @Test
    public void fullAccessUser_canCRUD() {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        // share at sampleAllAG level
        api.assertApiShare(resourceId, USER_ADMIN, FULL_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(FULL_ACCESS_USER.getName()); // wait until sharing info is populated

        // can share admin's resource with others since full access was granted
        assertSharingAccess(FULL_ACCESS_USER, LIMITED_ACCESS_USER);

        assertRUDAccess(FULL_ACCESS_USER);
    }

    @Test
    public void limitedAccessUser_canCRUD() {
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);
        // share at sampleAllAG level
        api.assertApiShare(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(LIMITED_ACCESS_USER.getName()); // wait until sharing info is populated

        assertSharingAccess(LIMITED_ACCESS_USER, FULL_ACCESS_USER);

        assertRUDAccess(LIMITED_ACCESS_USER);
    }

    @Test
    public void noAccessUser_canCRUD() {
        assertNoAccessBeforeSharing(NO_ACCESS_USER);
        // share at sampleAllAG level
        api.assertApiShare(resourceId, USER_ADMIN, NO_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
        api.awaitSharingEntry(NO_ACCESS_USER.getName());

        assertSharingAccess(NO_ACCESS_USER, LIMITED_ACCESS_USER);

        assertRUDAccess(NO_ACCESS_USER);
    }
}
