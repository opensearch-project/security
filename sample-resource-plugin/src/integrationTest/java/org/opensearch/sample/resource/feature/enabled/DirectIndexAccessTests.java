/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.directSharePayload;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.sampleAllAG;
import static org.opensearch.sample.resource.TestUtils.sampleReadOnlyAG;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing feature enabled. Tests exercise raw-document operations on the resource index.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ DirectIndexAccessTests.SystemIndexEnabled.class, DirectIndexAccessTests.SystemIndexDisabled.class })
public class DirectIndexAccessTests {

    /**
     * Only super-admins will be able to perform raw access request.
     * This is how the feature is intended to be utilized.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class SystemIndexEnabled {

        @ClassRule
        public static LocalCluster cluster = newCluster(true, true);

        private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
        private String id;

        private void assertResourceIndexAccess(String id, TestSecurityConfig.User user) {
            // cannot interact with resource index
            try (TestRestClient client = cluster.getRestClient(user)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(id, user, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(id, user, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, user, HttpStatus.SC_FORBIDDEN);

        }

        private void assertResourceSharingIndexAccess(String id, TestSecurityConfig.User user) {
            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(id, user, HttpStatus.SC_FORBIDDEN);
            api.assertDirectShare(id, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectRevoke(id, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectDeleteResourceSharingRecord(id, user, HttpStatus.SC_FORBIDDEN);
        }

        @Before
        public void setUp() {
            id = api.createRawResourceAs(cluster.getAdminCertificate());
            api.awaitSharingEntry("kirk");
        }

        @Test
        public void testRawAccess_noAccessUser() {
            // user has no permission
            assertResourceIndexAccess(id, NO_ACCESS_USER);
            assertResourceSharingIndexAccess(id, NO_ACCESS_USER);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            // user has read permission on resource index
            // since SIP is enabled, user will not be able to perform any raw requests

            assertResourceIndexAccess(id, LIMITED_ACCESS_USER);
            assertResourceSharingIndexAccess(id, LIMITED_ACCESS_USER);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            // user has * permission on all indices
            // since SIP is enabled, user will not be able to perform any raw requests

            assertResourceIndexAccess(id, FULL_ACCESS_USER);

            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(id, FULL_ACCESS_USER, HttpStatus.SC_NOT_FOUND);
            api.assertDirectShare(id, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectRevoke(id, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectDeleteResourceSharingRecord(id, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_superAdmin() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                // can access resource index directly
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + id, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);

                // can access resource sharing index directly
                client.get(RESOURCE_SHARING_INDEX + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(
                    RESOURCE_SHARING_INDEX + "/_doc/" + id,
                    directSharePayload(id, USER_ADMIN.getName(), NO_ACCESS_USER.getName(), sampleReadOnlyAG.name())
                ).assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_SHARING_INDEX + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);

                // can delete resource
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }

    /**
     * Users with permission to resource and its sharing index will be able to interact with them successfully.
     * Shows the importance of System-Index protection feature for this new authz mechanism, by showing what would happen if SIP is disabled and the feature is enabled.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class SystemIndexDisabled {

        @ClassRule
        public static LocalCluster cluster = newCluster(true, false);

        private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

        private String adminResId;

        @Before
        public void setup() {
            adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(); // wait until sharing entry is created
        }

        @Test
        public void testRawAccess_noAccessUser() {
            // user has no permission

            // cannot access any raw request
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectShare(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectRevoke(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectDeleteResourceSharingRecord(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            // user has read permission on resource index

            // cannot create a resource since user doesn't have indices:data/write/index permission
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // cannot read admin's resource directly since system index protection is enabled
            api.assertDirectGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            // once admin share's record, user can then query it directly
            api.assertDirectShare(adminResId, USER_ADMIN, LIMITED_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(LIMITED_ACCESS_USER.getName());
            api.assertDirectGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");

            // cannot update or delete resource
            api.assertDirectUpdate(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

            // cannot access resource sharing index since user doesn't have permissions on that index
            api.assertDirectViewSharingRecord(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectShare(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectRevoke(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectDeleteResourceSharingRecord(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            // user has * permission on all indices

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                userResId = resp.getTextFromJsonBody("/_id");
            }
            // cannot read admin's resource directly since resource is not shared with them
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            // once admin share's record, user can then query it directly
            api.assertDirectShare(adminResId, USER_ADMIN, FULL_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(FULL_ACCESS_USER.getName());
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");

            // admin cannot read user's resource until after they share it with admin
            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectShare(userResId, FULL_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sample");

            // cannot update or delete resource
            api.assertDirectUpdate(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            // can update and delete own resource
            api.assertDirectUpdate(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertDirectDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);

            // can view, share, revoke and delete resource sharing record(s) directly
            api.assertDirectViewSharingRecord(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertDirectShare(adminResId, FULL_ACCESS_USER, NO_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
            api.assertDirectRevoke(adminResId, FULL_ACCESS_USER, NO_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_OK);
            api.assertDirectDeleteResourceSharingRecord(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
        }

        @Test
        public void testRawAccess_superAdmin() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                // can access resource index directly
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + adminResId, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);

                // can access resource sharing index directly

                client.get(RESOURCE_SHARING_INDEX + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(
                    RESOURCE_SHARING_INDEX + "/_doc/" + adminResId,
                    directSharePayload(adminResId, USER_ADMIN.getName(), NO_ACCESS_USER.getName(), sampleReadOnlyAG.name())
                ).assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_SHARING_INDEX + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);

                // can delete resource
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
