/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.disabled;

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
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchAllPayload;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchByNamePayload;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_SEARCH_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This suite runs tests with resource sharing feature disabled. It tests direct access to the resource bypassing the sample plugin APIs.
 * There are two test classes. One with system index feature enabled, the other with disabled.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ DirectIndexAccessTests.SystemIndexEnabled.class, DirectIndexAccessTests.SystemIndexDisabled.class })
public class DirectIndexAccessTests {

    /**
     * No user except super-admin can access documents directly since system index protection is enabled
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class SystemIndexEnabled {

        @ClassRule
        public static LocalCluster cluster = newCluster(false, true);

        private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

        @After
        public void cleanup() {
            api.wipeOutResourceEntries();
        }

        @Test
        public void testRawAccess_noAccessUser() throws Exception {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            // user has no permissions

            // cannot access any raw request
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(id, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(id, NO_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);

            // search returns 403 since user doesn't have access to invoke search
            forbidden(() -> api.searchResourceIndex(NO_ACCESS_USER));
            forbidden(() -> api.searchResourceIndex(searchAllPayload(), NO_ACCESS_USER));
            forbidden(() -> api.searchResourceIndex(searchByNamePayload("sample"), NO_ACCESS_USER));

            api.assertDirectDelete(id, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // cannot create a resource since user doesn't have indices:data/write/index permission
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // cannot read admin's resource since system index protection is enabled, will show 404
            api.assertDirectGet(id, LIMITED_ACCESS_USER, HttpStatus.SC_NOT_FOUND, "");
            // cannot update or delete resource
            api.assertDirectUpdate(id, LIMITED_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);

            // should not be able to search for admin's resource, can not see any resource since system index protection is enabled
            api.assertDirectGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchAllPayload(), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sample"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sampleUser"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");

            api.assertDirectDelete(id, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            // user has * cluster and index permissions on all indices

            // cannot create a resource directly since system index protection (SIP) is enabled
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // cannot read admin's resource directly since SIP is enabled
            api.assertDirectGet(id, FULL_ACCESS_USER, HttpStatus.SC_NOT_FOUND, "sample");
            // cannot update or delete admin resource directly since SIP is enabled
            api.assertDirectUpdate(id, FULL_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);

            // should not be able to search for any resource since System index protection is enabled
            api.assertDirectGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchAllPayload(), FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sample"), FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sampleUser"), FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");

            api.assertDirectDelete(id, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_adminCertificateUser() {
            // super-admin can perform any operation
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                // can search resources
                client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchAllPayload()).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchByNamePayload("sampleUpdated")).assertStatusCode(HttpStatus.SC_OK);

                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + id, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }

    /**
     * Users with appropriate index permissions will be able to access and update resources directly, since system index protection is disabled
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class SystemIndexDisabled {

        @ClassRule
        public static LocalCluster cluster = newCluster(false, false);

        private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
        private String adminResId;

        @Before
        public void setup() {
            adminResId = api.createSampleResourceAs(USER_ADMIN);
        }

        @After
        public void cleanup() {
            api.wipeOutResourceEntries();
        }

        @Test
        public void testRawAccess_noAccessUser() {
            // user has no permissions

            // cannot access any raw request
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(adminResId, NO_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
            // should not be able to search for any resource
            api.assertDirectGetSearch(NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            api.assertDirectPostSearch(searchAllPayload(), NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            api.assertDirectPostSearch(searchByNamePayload("sampleUpdateAdmin"), NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");
            // can see own resource
            api.assertDirectPostSearch(searchByNamePayload("sampleUser"), NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, 0, "");

            api.assertDirectDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // cannot create a resource since user doesn't have indices:data/write/index permission
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // can read admin's resource
            api.assertDirectGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
            // cannot update or delete resource since user doesn't have update and delete permissions
            api.assertDirectUpdate(adminResId, LIMITED_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);

            // should be able to search only for one resource, admin's
            api.assertDirectGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sample");
            api.assertDirectPostSearch(searchAllPayload(), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sample");
            api.assertDirectPostSearch(searchByNamePayload("sample"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sample");
            // can see own resource
            api.assertDirectPostSearch(searchByNamePayload("sampleUser"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");

            api.assertDirectDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            // user has * cluster and index permissions on all indices

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\",\"resource_type\":\"" + RESOURCE_TYPE + "\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                userResId = resp.getTextFromJsonBody("/_id");
            }
            // can read admin's resource
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
            api.assertDirectGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUser");
            // can update and delete all resources
            api.assertDirectUpdate(adminResId, FULL_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_OK);
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdateAdmin");
            api.assertDirectUpdate(userResId, FULL_ACCESS_USER, "sampleUpdateUser", HttpStatus.SC_OK);
            api.assertDirectGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdateUser");

            // should be able to search for all resources
            api.assertDirectGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 2, "sampleUpdateUser");
            api.assertDirectPostSearch(searchAllPayload(), FULL_ACCESS_USER, HttpStatus.SC_OK, 2, "sampleUpdateUser");
            api.assertDirectPostSearch(searchByNamePayload("sampleUpdateUser"), FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");
            // can see own resource
            api.assertDirectPostSearch(
                searchByNamePayload("sampleUpdateAdmin"),
                FULL_ACCESS_USER,
                HttpStatus.SC_OK,
                1,
                "sampleUpdateAdmin"
            );

            api.assertDirectDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertDirectDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);

            api.assertDirectGet(adminResId, USER_ADMIN, HttpStatus.SC_NOT_FOUND, "");
            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_NOT_FOUND, "");
        }

        @Test
        public void testRawAccess_adminCertificateUser() {
            // super-admin can perform any operation
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + adminResId, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);
                // can search resources
                client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchAllPayload()).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchByNamePayload("sampleUpdated")).assertStatusCode(HttpStatus.SC_OK);

                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
