/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import java.util.Map;
import java.util.Set;

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
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.assertSearchResponse;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchAllPayload;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchByNamePayload;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_SEARCH_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.putSharingInfoPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.security.api.AbstractApiIntegrationTest.ok;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing feature enabled and system index protection enabled
 * Only users with appropriate access to resources will be allowed via APIs and via direct index access since SIP is disabled.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ ApiAccessTests.SystemIndexEnabled.class, ApiAccessTests.SystemIndexDisabled.class })
public class ApiAccessTests {

    /**
     * Users can only access resources they are shared with or owner of.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class SystemIndexEnabled {

        @ClassRule
        public static LocalCluster cluster = newCluster(true, true);

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
        public void testPluginInstalledCorrectly() {
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                HttpResponse plugins = client.get("_cat/plugins");
                assertThat(plugins.getBody(), containsString("OpenSearchSecurityPlugin"));
                assertThat(plugins.getBody(), containsString("SampleResourcePlugin"));
            }
        }

        @Test
        public void testResourceSharingIndexExists() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_search");
                resp.assertStatusCode(HttpStatus.SC_OK);
            }
        }

        @Test
        public void testApiAccess_noAccessUser() throws Exception {
            // user has no permission

            // cannot create own resource
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // cannot get admin's resource
            forbidden(() -> api.getResource(adminResId, NO_ACCESS_USER));
            // cannot update admin's resource
            forbidden(() -> api.updateResource(adminResId, NO_ACCESS_USER, "sampleUpdateAdmin"));
            TestRestClient.HttpResponse response = ok(() -> api.getResource(adminResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sample"));

            // cannot share admin's resource with itself
            forbidden(() -> api.shareResource(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, SAMPLE_READ_ONLY));
            forbidden(() -> api.revokeResource(adminResId, NO_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));

            // cannot see admin's resource when searching
            forbidden(() -> api.searchResources(NO_ACCESS_USER));
            forbidden(() -> api.searchResources(searchAllPayload(), NO_ACCESS_USER));
            forbidden(() -> api.searchResources(searchByNamePayload("sample"), NO_ACCESS_USER));

            // cannot delete admin's resource
            forbidden(() -> api.deleteResource(adminResId, NO_ACCESS_USER));
            response = ok(() -> api.getResource(adminResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sample"));
        }

        @Test
        public void testApiAccess_limitedAccessUser() throws Exception {
            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            api.awaitSharingEntry(userResId, LIMITED_ACCESS_USER.getName());

            // cannot see admin's resource
            forbidden(() -> api.getResource(adminResId, LIMITED_ACCESS_USER));
            TestRestClient.HttpResponse listResponse = ok(() -> api.listResources(LIMITED_ACCESS_USER)); // can only see own resource
            assertThat(listResponse.getBody(), containsString("sampleUser"));

            // cannot update admin's resource
            forbidden(() -> api.updateResource(adminResId, LIMITED_ACCESS_USER, "sampleUpdateAdmin"));
            TestRestClient.HttpResponse response = ok(() -> api.getResource(adminResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sample"));
            // can update own resource
            ok(() -> api.updateResource(userResId, LIMITED_ACCESS_USER, "sampleUpdateUser"));
            response = ok(() -> api.getResource(userResId, LIMITED_ACCESS_USER));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));
            // resource should be visible even after update

            api.assertApiGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");

            // cannot share or revoke admin's resource
            forbidden(() -> api.shareResource(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));
            forbidden(() -> api.revokeResource(adminResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));

            // can share or revoke own resource
            forbidden(() -> api.getResource(userResId, USER_ADMIN));
            ok(() -> api.shareResource(userResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));
            response = ok(() -> api.getResource(userResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));
            ok(() -> api.revokeResource(userResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));
            forbidden(() -> api.getResource(userResId, USER_ADMIN));

            // should not be able to search for admin's resource, can only see self-resource
            TestRestClient.HttpResponse searchResponse = ok(() -> api.searchResources(LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchAllPayload(), LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sample"), LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 0, null);
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sampleUpdateUser"), LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");

            // can delete own resource since user is the owner
            ok(() -> api.deleteResource(userResId, LIMITED_ACCESS_USER));
            // cannot delete admin's resource
            forbidden(() -> api.deleteResource(adminResId, LIMITED_ACCESS_USER));
        }

        @Test
        public void testApiAccess_allAccessUser() throws Exception {
            // user has * cluster and index permissions

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }
            api.awaitSharingEntry(userResId, FULL_ACCESS_USER.getName());

            // cannot see admin's resource
            forbidden(() -> api.getResource(adminResId, FULL_ACCESS_USER));
            TestRestClient.HttpResponse listResponse = ok(() -> api.listResources(FULL_ACCESS_USER));
            assertThat(listResponse.getBody(), containsString("sampleUser"));

            // cannot update admin's resource
            forbidden(() -> api.updateResource(adminResId, FULL_ACCESS_USER, "sampleUpdateAdmin"));
            // can update own resource
            ok(() -> api.updateResource(userResId, FULL_ACCESS_USER, "sampleUpdateUser"));
            TestRestClient.HttpResponse response = ok(() -> api.getResource(userResId, FULL_ACCESS_USER));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));
            // resource should be visible even after update
            api.assertApiGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");

            // cannot share or revoke admin's resource
            forbidden(() -> api.shareResource(adminResId, FULL_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_READ_ONLY));
            forbidden(() -> api.revokeResource(adminResId, FULL_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));

            // can share or revoke own resource
            forbidden(() -> api.getResource(userResId, LIMITED_ACCESS_USER));
            ok(() -> api.shareResource(userResId, FULL_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));
            response = ok(() -> api.getResource(userResId, LIMITED_ACCESS_USER));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));
            api.assertApiPostSearch(searchByNamePayload("sampleUpdateUser"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");
            ok(() -> api.revokeResource(userResId, FULL_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));
            forbidden(() -> api.getResource(userResId, LIMITED_ACCESS_USER));

            // should not be able to search for admin's resource, 1 total result
            TestRestClient.HttpResponse searchResponse = ok(() -> api.searchResources(FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchAllPayload(), FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sample"), FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 0, null);
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sampleUpdateUser"), FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");

            // can delete own resource
            ok(() -> api.deleteResource(userResId, FULL_ACCESS_USER));
            // cannot delete admin's resource
            forbidden(() -> api.deleteResource(adminResId, FULL_ACCESS_USER));
        }

        @Test
        public void testApiAccess_superAdmin() {
            // can see admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));

                // can update admin's resource
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                // can share and revoke admin's resource
                resp = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, NO_ACCESS_USER.getName())
                );

                resp.assertStatusCode(HttpStatus.SC_OK);

                TestUtils.PatchSharingInfoPayloadBuilder payloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
                payloadBuilder.resourceId(adminResId);
                payloadBuilder.resourceType(RESOURCE_TYPE);
                payloadBuilder.revoke(new Recipients(Map.of(Recipient.USERS, Set.of(NO_ACCESS_USER.getName()))), SAMPLE_FULL_ACCESS);
                resp = client.patch(SECURITY_SHARE_ENDPOINT, payloadBuilder.build());

                resp.assertStatusCode(HttpStatus.SC_OK);

                // can search resources
                resp = client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                resp = client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchAllPayload());
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                resp = client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchByNamePayload("sampleUpdated"));
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                // can delete admin's resource
                resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }

        }
    }

    /**
     * Users will only be able to access resources they are shared_with or owner of, via plugin APIs, even if system index protection is disabled.
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
            api.awaitSharingEntry(adminResId);
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
        public void testResourceSharingIndexExists() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_search");
                resp.assertStatusCode(HttpStatus.SC_OK);
            }
        }

        @Test
        public void testApiAccess_noAccessUser() throws Exception {
            // user has no permission

            // cannot create own resource
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // cannot get admin's resource
            forbidden(() -> api.getResource(adminResId, NO_ACCESS_USER));
            // cannot update admin's resource
            forbidden(() -> api.updateResource(adminResId, NO_ACCESS_USER, "sampleUpdateAdmin"));
            TestRestClient.HttpResponse response = ok(() -> api.getResource(adminResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sample"));

            // cannot share admin's resource with itself
            forbidden(() -> api.shareResource(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, SAMPLE_READ_ONLY));
            forbidden(() -> api.revokeResource(adminResId, NO_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));

            // should not be able to search for any resource
            forbidden(() -> api.searchResources(NO_ACCESS_USER));
            forbidden(() -> api.searchResources(searchAllPayload(), NO_ACCESS_USER));
            forbidden(() -> api.searchResources(searchByNamePayload("sampleUpdateAdmin"), NO_ACCESS_USER));
            forbidden(() -> api.searchResources(searchByNamePayload("sampleUpdateUser"), NO_ACCESS_USER));

            // cannot delete admin's resource
            forbidden(() -> api.deleteResource(adminResId, NO_ACCESS_USER));
            response = ok(() -> api.getResource(adminResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sample"));
        }

        @Test
        public void testApiAccess_limitedAccessUser() throws Exception {
            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            api.awaitSharingEntry(userResId, LIMITED_ACCESS_USER.getName());

            // cannot see admin's resource
            forbidden(() -> api.getResource(adminResId, LIMITED_ACCESS_USER));
            TestRestClient.HttpResponse listResponse = ok(() -> api.listResources(LIMITED_ACCESS_USER)); // can only see own resource
            assertThat(listResponse.getBody(), containsString("sampleUser"));

            // cannot update admin's resource
            forbidden(() -> api.updateResource(adminResId, LIMITED_ACCESS_USER, "sampleUpdateAdmin"));
            TestRestClient.HttpResponse response = ok(() -> api.getResource(adminResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sample"));
            // can update own resource
            ok(() -> api.updateResource(userResId, LIMITED_ACCESS_USER, "sampleUpdateUser"));
            response = ok(() -> api.getResource(userResId, LIMITED_ACCESS_USER));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));

            // cannot share or revoke admin's resource
            forbidden(() -> api.shareResource(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY));
            forbidden(() -> api.revokeResource(adminResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));

            // can share or revoke own resource
            forbidden(() -> api.getResource(userResId, USER_ADMIN));
            ok(() -> api.shareResource(userResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));
            response = ok(() -> api.getResource(userResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));
            ok(() -> api.revokeResource(userResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));
            forbidden(() -> api.getResource(userResId, USER_ADMIN));

            // should be able to search only for own resource
            TestRestClient.HttpResponse searchResponse = ok(() -> api.searchResources(LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchAllPayload(), LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sample"), LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 0, null);
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sampleUpdateUser"), LIMITED_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");

            // can delete own resource since user is the owner
            ok(() -> api.deleteResource(userResId, LIMITED_ACCESS_USER));
            // cannot delete admin's resource
            forbidden(() -> api.deleteResource(adminResId, LIMITED_ACCESS_USER));
        }

        @Test
        public void testApiAccess_allAccessUser() throws Exception {
            // user has * cluster and index permissions

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            api.awaitSharingEntry(userResId, FULL_ACCESS_USER.getName());

            // cannot see admin's resource
            forbidden(() -> api.getResource(adminResId, FULL_ACCESS_USER));
            TestRestClient.HttpResponse listResponse = ok(() -> api.listResources(FULL_ACCESS_USER));
            assertThat(listResponse.getBody(), containsString("sampleUser"));

            // cannot update admin's resource as resource is not shared with itself
            forbidden(() -> api.updateResource(adminResId, FULL_ACCESS_USER, "sampleUpdateAdmin"));
            // can update own resource
            ok(() -> api.updateResource(userResId, FULL_ACCESS_USER, "sampleUpdateUser"));
            TestRestClient.HttpResponse response = ok(() -> api.getResource(userResId, FULL_ACCESS_USER));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));

            // cannot share or revoke admin's resource
            forbidden(() -> api.shareResource(adminResId, FULL_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_READ_ONLY));
            forbidden(() -> api.revokeResource(adminResId, FULL_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));

            // can share or revoke own resource
            forbidden(() -> api.getResource(userResId, USER_ADMIN));
            ok(() -> api.shareResource(userResId, FULL_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));
            response = ok(() -> api.getResource(userResId, USER_ADMIN));
            assertThat(response.getBody(), containsString("sampleUpdateUser"));
            ok(() -> api.revokeResource(userResId, FULL_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY));
            forbidden(() -> api.getResource(userResId, USER_ADMIN));

            // should be able to search only for its own resource
            TestRestClient.HttpResponse searchResponse = ok(() -> api.searchResources(FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchAllPayload(), FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sample"), FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 0, null);
            searchResponse = ok(() -> api.searchResources(searchByNamePayload("sampleUpdateUser"), FULL_ACCESS_USER));
            assertSearchResponse(searchResponse, 1, "sampleUpdateUser");

            // can delete own resource
            ok(() -> api.deleteResource(userResId, FULL_ACCESS_USER));
            // cannot delete admin's resource
            forbidden(() -> api.deleteResource(adminResId, FULL_ACCESS_USER));
        }

        @Test
        public void testApiAccess_superAdmin() {

            // can see admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));

                // can update admin's resource
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                // can share and revoke admin's resource
                resp = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, NO_ACCESS_USER.getName())
                );

                resp.assertStatusCode(HttpStatus.SC_OK);

                TestUtils.PatchSharingInfoPayloadBuilder payloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
                payloadBuilder.resourceId(adminResId);
                payloadBuilder.resourceType(RESOURCE_TYPE);
                payloadBuilder.revoke(new Recipients(Map.of(Recipient.USERS, Set.of(NO_ACCESS_USER.getName()))), SAMPLE_FULL_ACCESS);
                resp = client.patch(SECURITY_SHARE_ENDPOINT, payloadBuilder.build());

                resp.assertStatusCode(HttpStatus.SC_OK);

                // can search resources
                resp = client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                resp = client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchAllPayload());
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                resp = client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchByNamePayload("sampleUpdated"));
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));

                // can delete admin's resource
                resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }

        }
    }

}
