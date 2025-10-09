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
import org.junit.After;
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

import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchAllPayload;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchByNamePayload;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS_RESOURCE_AG;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY_RESOURCE_AG;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_SEARCH_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.directSharePayload;
import static org.opensearch.sample.resource.TestUtils.newCluster;
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
            if (NO_ACCESS_USER.getName().equals(user.getName())) {
                api.assertDirectGet(id, user, HttpStatus.SC_FORBIDDEN, "");
            } else {
                api.assertDirectGet(id, user, HttpStatus.SC_NOT_FOUND, "");
            }
            api.assertDirectUpdate(id, user, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);

            api.assertDirectDelete(id, user, HttpStatus.SC_FORBIDDEN);

        }

        private void assertResourceSharingIndexAccess(String id, TestSecurityConfig.User user) {
            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(id, user, HttpStatus.SC_FORBIDDEN);
            api.assertDirectUpdateSharingInfo(id, user, user, SAMPLE_FULL_ACCESS_RESOURCE_AG, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDeleteResourceSharingRecord(id, user, HttpStatus.SC_FORBIDDEN);
        }

        @Before
        public void setUp() {
            id = api.createRawResourceAs(cluster.getAdminCertificate());
            api.awaitSharingEntry(id, "kirk");
        }

        @After
        public void cleanup() {
            api.wipeOutResourceEntries();
        }

        @Test
        public void testRawAccess_noAccessUser() {
            // user has no permission
            assertResourceIndexAccess(id, NO_ACCESS_USER);
            // cannot access directly since System index protection is enabled
            api.assertDirectGetSearch(NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            api.assertDirectPostSearch(searchAllPayload(), NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sample"), NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            assertResourceSharingIndexAccess(id, NO_ACCESS_USER);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            // user has read permission on resource index
            // since SIP is enabled, user will not be able to perform any raw requests

            assertResourceIndexAccess(id, LIMITED_ACCESS_USER);
            // cannot access directly since System index protection is enabled
            api.assertDirectGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchAllPayload(), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sample"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            assertResourceSharingIndexAccess(id, LIMITED_ACCESS_USER);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            // user has * permission on all indices
            // since SIP is enabled, user will not be able to perform any raw requests

            assertResourceIndexAccess(id, FULL_ACCESS_USER);

            // cannot access directly since System index protection is enabled
            api.assertDirectGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchAllPayload(), FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sample"), FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");

            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(id, FULL_ACCESS_USER, HttpStatus.SC_NOT_FOUND);
            api.assertDirectUpdateSharingInfo(
                id,
                FULL_ACCESS_USER,
                FULL_ACCESS_USER,
                SAMPLE_FULL_ACCESS_RESOURCE_AG,
                HttpStatus.SC_FORBIDDEN
            );
            api.assertDirectDeleteResourceSharingRecord(id, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_superAdmin() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                // can access resource index directly
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + id, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);

                // can search resources
                client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchAllPayload()).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchByNamePayload("sampleUpdated")).assertStatusCode(HttpStatus.SC_OK);

                // can access resource sharing index directly
                client.get(RESOURCE_SHARING_INDEX + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(
                    RESOURCE_SHARING_INDEX + "/_doc/" + id,
                    directSharePayload(id, USER_ADMIN.getName(), NO_ACCESS_USER.getName(), SAMPLE_READ_ONLY_RESOURCE_AG)
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
            api.awaitSharingEntry(adminResId); // wait until sharing entry is created
        }

        @After
        public void cleanup() {
            api.wipeOutResourceEntries();
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
            api.assertDirectUpdate(adminResId, NO_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

            // cannot access directly since user doesn't have index access
            api.assertDirectGetSearch(NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            api.assertDirectPostSearch(searchAllPayload(), NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sample"), NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "sample");

            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectUpdateSharingInfo(
                adminResId,
                NO_ACCESS_USER,
                NO_ACCESS_USER,
                SAMPLE_FULL_ACCESS_RESOURCE_AG,
                HttpStatus.SC_FORBIDDEN
            );
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
            api.assertDirectGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
            // once admin share's record, user can then query it directly
            api.assertDirectUpdateSharingInfo(adminResId, USER_ADMIN, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY_RESOURCE_AG, HttpStatus.SC_OK);
            api.awaitSharingEntry(adminResId, LIMITED_ACCESS_USER.getName());
            api.assertDirectGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");

            // should be able to access the record since user has direct index access
            api.assertDirectGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sample");
            api.assertDirectPostSearch(searchAllPayload(), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sample");
            api.assertDirectPostSearch(searchByNamePayload("sample"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sample");

            // cannot update or delete resource
            api.assertDirectUpdate(adminResId, LIMITED_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

            // cannot access resource sharing index since user doesn't have permissions on that index
            api.assertDirectViewSharingRecord(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectUpdateSharingInfo(
                adminResId,
                LIMITED_ACCESS_USER,
                LIMITED_ACCESS_USER,
                SAMPLE_FULL_ACCESS_RESOURCE_AG,
                HttpStatus.SC_FORBIDDEN
            );
            api.assertDirectDeleteResourceSharingRecord(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            // user has * permission on all indices

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc?refresh=true", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                userResId = resp.getTextFromJsonBody("/_id");
            }
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
            // once admin share's record, user can then query it directly
            api.assertDirectUpdateSharingInfo(adminResId, USER_ADMIN, FULL_ACCESS_USER, SAMPLE_READ_ONLY_RESOURCE_AG, HttpStatus.SC_OK);
            api.awaitSharingEntry(adminResId, FULL_ACCESS_USER.getName());
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");

            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
            api.assertDirectUpdateSharingInfo(userResId, FULL_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY_RESOURCE_AG, HttpStatus.SC_OK);
            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sample");

            api.assertDirectGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 2, "sample");
            api.assertDirectPostSearch(searchAllPayload(), FULL_ACCESS_USER, HttpStatus.SC_OK, 2, "sample");
            api.assertDirectPostSearch(searchByNamePayload("sample"), FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sample");
            api.assertDirectPostSearch(searchByNamePayload("sampleUser"), FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUser");

            // can update and delete own resource
            api.assertDirectUpdate(userResId, FULL_ACCESS_USER, "sampleUpdateUser", HttpStatus.SC_OK);
            api.assertDirectDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);

            // can view, share, revoke and delete resource sharing record(s) directly
            api.assertDirectViewSharingRecord(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertDirectUpdateSharingInfo(
                adminResId,
                FULL_ACCESS_USER,
                NO_ACCESS_USER,
                SAMPLE_FULL_ACCESS_RESOURCE_AG,
                HttpStatus.SC_OK
            );
            api.assertDirectDeleteResourceSharingRecord(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);

            // can update or delete admin resource, since system index protection is disabled and user has direct index access.
            api.assertDirectUpdate(adminResId, FULL_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_OK);
            api.assertDirectDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
        }

        @Test
        public void testRawAccess_superAdmin() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                // can access resource index directly
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + adminResId, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);

                // can search resources
                client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchAllPayload()).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchByNamePayload("sampleUpdated")).assertStatusCode(HttpStatus.SC_OK);

                // can access resource sharing index directly

                client.get(RESOURCE_SHARING_INDEX + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(
                    RESOURCE_SHARING_INDEX + "/_doc/" + adminResId,
                    directSharePayload(adminResId, USER_ADMIN.getName(), NO_ACCESS_USER.getName(), SAMPLE_READ_ONLY_RESOURCE_AG)
                ).assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_SHARING_INDEX + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);

                // can delete resource
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
