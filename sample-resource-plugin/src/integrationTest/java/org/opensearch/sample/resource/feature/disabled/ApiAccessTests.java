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
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_REVOKE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.revokeAccessPayload;
import static org.opensearch.sample.resource.TestUtils.sampleAllAG;
import static org.opensearch.sample.resource.TestUtils.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestUtils.shareWithPayload;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This suite runs tests with resource sharing feature disabled. It tests access to sample plugin APIs.
 * There are two test classes. One with system index feature enabled, the other with disabled.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ ApiAccessTests.SystemIndexEnabled.class, ApiAccessTests.SystemIndexDisabled.class })
public class ApiAccessTests {

    /**
     * Tests exercising the plugin API endpoints
     * Only those users with appropriate index permissions will be able to access resources via APIs
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class SystemIndexEnabled {

        @ClassRule
        public static LocalCluster cluster = newCluster(false, true);

        private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
        private String adminResId;

        @Before
        public void setup() {
            adminResId = api.createSampleResourceAs(USER_ADMIN);
        }

        @Test
        public void testPluginInstalledCorrectly() {
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                HttpResponse plugins = client.get("_cat/plugins");
                assertThat(plugins.getBody(), containsString("OpenSearchSecurityPlugin"));
                assertThat(plugins.getBody(), containsString("SampleResourcePlugin"));
            }
        }

        @Test
        public void testResourceSharingIndexDoesntExist() {
            // when feature is disabled, no resource-sharing index should be created
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_search");
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }
        }

        @Test
        public void testApiAccess_noAccessUser() {
            // user with no permissions

            // cannot create own resource
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // cannot get admin's resource
            api.assertApiGet(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            // cannot update admin's resource
            api.assertApiUpdate(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");

            // feature is disabled, no handler's exist
            api.assertApiShare(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);
            api.assertApiRevoke(adminResId, NO_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // cannot delete admin's resource
            api.assertApiDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testApiAccess_limitedAccessUser() {
            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource
            api.assertApiGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
            // cannot update admin's resource since user doesn't have update permission
            api.assertApiUpdate(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
            // cannot update own resource since user doesn't have update permission
            api.assertApiUpdate(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

            // feature is disabled, no handler's exist
            api.assertApiShare(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);
            api.assertApiRevoke(adminResId, LIMITED_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // cannot delete own resource since user doesn't have delete permission
            api.assertApiDelete(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            // cannot delete admin's resource since user doesn't have delete permission
            api.assertApiDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testApiAccess_allAccessUser() {
            // user has * cluster and index permissions

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource since feature is disabled and user has * permissions
            api.assertApiGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");

            // can update admin's resource since feature is disabled and user has * permissions
            api.assertApiUpdate(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertApiGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdated");
            // can update own resource since feature is disabled and user has * permissions
            api.assertApiUpdate(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertApiGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdated");

            // feature is disabled, no handler's exist
            api.assertApiShare(adminResId, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);
            api.assertApiRevoke(adminResId, FULL_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // can delete own resource since user has * permissions
            api.assertApiDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            // can delete admin's resource since feature is disabled and user has * permissions
            api.assertApiDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_NOT_FOUND, "");
        }

        @Test
        public void testApiAccess_adminCertificateUsers() {
            // super-admin can perform any operation

            // can see admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));
            }

            // can update admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                TestRestClient.HttpResponse resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));
            }

            // can't share or revoke, as handlers don't exist
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                TestRestClient.HttpResponse response = client.postJson(
                    SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + adminResId,
                    shareWithPayload(FULL_ACCESS_USER.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);

                response = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + adminResId,
                    revokeAccessPayload(FULL_ACCESS_USER.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            }

            // can delete admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }
        }
    }

    /**
     * Tests exercising the plugin API endpoints.
     * All users can access all resources through the plugin APIs given they have appropriate index permission, since system index protection is disabled
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class SystemIndexDisabled {

        @ClassRule
        public static LocalCluster cluster = newCluster(false, false);

        private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

        @Test
        public void testPluginInstalledCorrectly() {
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                HttpResponse plugins = client.get("_cat/plugins");
                assertThat(plugins.getBody(), containsString("OpenSearchSecurityPlugin"));
                assertThat(plugins.getBody(), containsString("SampleResourcePlugin"));
            }
        }

        @Test
        public void testResourceSharingIndexDoesntExist() {
            api.createSampleResourceAs(USER_ADMIN);
            // when feature is disabled, no resource-sharing index should be created
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_search");
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }
        }

        @Test
        public void testApiAccess_noAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user has no permissions

            // cannot create own resource
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // cannot get admin's resource
            api.assertApiGet(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            // cannot update admin's resource
            api.assertApiUpdate(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");

            // feature is disabled, no handler's exist
            api.assertApiShare(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);
            api.assertApiRevoke(adminResId, NO_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // cannot delete admin's resource
            api.assertApiDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testApiAccess_limitedAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource
            api.assertApiGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
            // cannot update admin's resource
            api.assertApiUpdate(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
            // cannot update own resource
            api.assertApiUpdate(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

            // feature is disabled, no handler's exist
            api.assertApiShare(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);
            api.assertApiRevoke(adminResId, LIMITED_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // cannot delete resource since feature is disabled and user doesn't have delete permission
            api.assertApiDelete(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            // cannot delete admin's resource since user doesn't have delete permission
            api.assertApiDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testApiAccess_allAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user has * cluster and * index permissions on all indices

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource
            api.assertApiGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");

            // can update admin's resource
            api.assertApiUpdate(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertApiGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdated");
            // can update a resource
            api.assertApiUpdate(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertApiGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdated");

            // feature is disabled, no handler's exist
            api.assertApiShare(adminResId, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);
            api.assertApiRevoke(adminResId, FULL_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // can delete a resource
            api.assertApiDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            // can delete admin's resource
            api.assertApiDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_NOT_FOUND, "");
        }

        @Test
        public void testApiAccess_adminCertificateUser() {
            String id = api.createSampleResourceAs(USER_ADMIN);
            // can see all resources
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));

                // can update all resources
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + id, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                // can't share or revoke, as handlers don't exist
                resp = client.postJson(
                    SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + id,
                    shareWithPayload(FULL_ACCESS_USER.getName(), sampleAllAG.name())
                );
                resp.assertStatusCode(HttpStatus.SC_BAD_REQUEST);

                resp = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + id,
                    revokeAccessPayload(FULL_ACCESS_USER.getName(), sampleAllAG.name())
                );
                resp.assertStatusCode(HttpStatus.SC_BAD_REQUEST);

                // can delete admin's resource
                resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }

        }
    }

}
