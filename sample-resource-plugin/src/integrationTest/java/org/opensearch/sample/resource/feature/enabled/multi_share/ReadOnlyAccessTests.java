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

import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.sampleFullAccessResourceAG;
import static org.opensearch.sample.resource.TestUtils.sampleReadOnlyResourceAG;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access to a resource shared with read-only access-level.
 * All tests are against USER_ADMIN's resource created during setup.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ReadOnlyAccessTests {
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
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(RESOURCE_SHARING_INDEX);
        }
    }

    private void assertNoAccessBeforeSharing(TestSecurityConfig.User user) {
        api.assertApiGet(resourceId, user, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiUpdate(resourceId, user, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

        api.assertApiShare(resourceId, user, user, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(resourceId, user, user, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
    }

    private void assertReadOnly(TestSecurityConfig.User user) {
        api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, user, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

        api.assertApiShare(resourceId, user, user, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(resourceId, user, user, sampleFullAccessResourceAG, HttpStatus.SC_FORBIDDEN);
    }

    @Test
    public void fullAccessUser_canRead_cannotUpdateDeleteShareRevoke() {
        assertNoAccessBeforeSharing(FULL_ACCESS_USER);
        // share at sampleReadOnly level
        api.assertApiShare(resourceId, USER_ADMIN, FULL_ACCESS_USER, sampleReadOnlyResourceAG, HttpStatus.SC_OK);
        api.awaitSharingEntry(FULL_ACCESS_USER.getName()); // wait until sharing info is populated
        assertReadOnly(FULL_ACCESS_USER);
    }

    @Test
    public void limitedAccessUser_canRead_cannotUpdateDeleteShareRevoke() {
        assertNoAccessBeforeSharing(LIMITED_ACCESS_USER);
        // share at sampleReadOnly level
        api.assertApiShare(resourceId, USER_ADMIN, LIMITED_ACCESS_USER, sampleReadOnlyResourceAG, HttpStatus.SC_OK);
        api.awaitSharingEntry(LIMITED_ACCESS_USER.getName()); // wait until sharing info is populated
        assertReadOnly(LIMITED_ACCESS_USER);
    }

    @Test
    public void noAccessUser_canRead_cannotUpdateDeleteShareRevoke() {
        assertNoAccessBeforeSharing(NO_ACCESS_USER);
        // share at sampleReadOnly level
        api.assertApiShare(resourceId, USER_ADMIN, NO_ACCESS_USER, sampleReadOnlyResourceAG, HttpStatus.SC_OK);
        api.awaitSharingEntry(NO_ACCESS_USER.getName()); // wait until sharing info is populated
        assertReadOnly(NO_ACCESS_USER);
    }

}
