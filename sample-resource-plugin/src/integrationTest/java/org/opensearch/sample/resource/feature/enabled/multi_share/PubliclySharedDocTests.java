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
import static org.opensearch.sample.resource.TestUtils.sampleFullAccessResourceAG;
import static org.opensearch.sample.resource.TestUtils.sampleReadOnlyResourceAG;
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

        api.assertApiShare(resourceId, user, user, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(resourceId, user, user, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
    }

    private void assertReadOnly() {
        api.assertApiGet(resourceId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, FULL_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(resourceId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

        api.assertApiShare(resourceId, FULL_ACCESS_USER, TestUtils.FULL_ACCESS_USER, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(resourceId, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
    }

    private void assertFullAccess() {
        api.assertApiGet(resourceId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, LIMITED_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_OK);
        api.assertApiShare(resourceId, LIMITED_ACCESS_USER, TestUtils.LIMITED_ACCESS_USER, sampleFullAccessResourceAG, HttpStatus.SC_OK);
        api.assertApiRevoke(resourceId, LIMITED_ACCESS_USER, USER_ADMIN, sampleFullAccessResourceAG, HttpStatus.SC_OK);
        api.awaitSharingEntry();
        api.assertApiDelete(resourceId, LIMITED_ACCESS_USER, HttpStatus.SC_OK);
    }

    @Test
    public void readOnly() {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        // 1. share at read-only for full-access user and at full-access for limited perms user
        api.assertApiShare(resourceId, USER_ADMIN, new TestSecurityConfig.User("*"), sampleReadOnlyResourceAG, HttpStatus.SC_OK);
        api.awaitSharingEntry("*");

        // 2. check read-only access for full-access user
        assertReadOnly();
    }

    @Test
    public void fullAccess() {
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);
        // 1. share at read-only for full-access user and at full-access for limited perms user
        api.assertApiShare(resourceId, USER_ADMIN, new TestSecurityConfig.User("*"), sampleFullAccessResourceAG, HttpStatus.SC_OK);
        api.awaitSharingEntry("*");

        // 2. check read-only access for full-access user
        assertFullAccess();
    }

}
