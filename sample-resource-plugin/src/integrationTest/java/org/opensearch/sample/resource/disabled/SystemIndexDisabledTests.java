/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.disabled;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope.Scope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.opensearch.Version;
import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.resource.TestHelper;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SHARED_WITH_USER_FULL_ACCESS;
import static org.opensearch.sample.resource.TestHelper.SHARED_WITH_USER_LIMITED_ACCESS;
import static org.opensearch.sample.resource.TestHelper.SHARED_WITH_USER_NO_ACCESS;
import static org.opensearch.sample.resource.TestHelper.sampleAllAG;
import static org.opensearch.sample.resource.TestHelper.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

// Top-level suite that groups both API and raw-document tests
@RunWith(Suite.class)
@Suite.SuiteClasses({ SystemIndexDisabledTests.ApiAccessTests.class, SystemIndexDisabledTests.RawDocumentAccessTests.class })
public class SystemIndexDisabledTests {

    private static final String RESOURCE_SHARING_INDEX = getSharingIndex(RESOURCE_INDEX_NAME);

    /**
     * Base test class providing shared cluster setup and teardown
     */
    public static abstract class BaseTests {
        @ClassRule
        public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .plugin(PainlessModulePlugin.class)
            .plugin(
                new PluginInfo(
                    SampleResourcePlugin.class.getName(),
                    "classpath plugin",
                    "NA",
                    Version.CURRENT,
                    "1.8",
                    SampleResourcePlugin.class.getName(),
                    null,
                    List.of(OpenSearchSecurityPlugin.class.getName()),
                    false
                )
            )
            .anonymousAuth(true)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, SHARED_WITH_USER_LIMITED_ACCESS, SHARED_WITH_USER_NO_ACCESS)
            .actionGroups(sampleReadOnlyAG, sampleAllAG)
            .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
            .build();

        @After
        public void clearIndices() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.delete(RESOURCE_INDEX_NAME);
                client.delete(RESOURCE_SHARING_INDEX);
            }
        }
    }

    /**
     * Tests exercising the plugin API endpoints
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(Scope.NONE)
    public static class ApiAccessTests extends BaseTests {

        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

        @Test
        public void testPluginInstalledCorrectly() {
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                String body = client.get("_cat/plugins").getBody();
                assertThat(body, containsString("OpenSearchSecurityPlugin"));
                assertThat(body, containsString("SampleResourcePlugin"));
            }
        }

        @Test
        public void testCRUD_noAccessUser() {
            String id = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

            // user doesn't have any permissions

            // cannot create own resource
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_NO_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // cannot get resource
            api.assertApiGet(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiGetAll(SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            // cannot update resource
            api.assertApiUpdate(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            // cannot delete resource
            api.assertApiDelete(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            // cannot share admin's resource with itself
            api.assertApiShare(
                id,
                SHARED_WITH_USER_NO_ACCESS,
                SHARED_WITH_USER_NO_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            // can view admin's resource once admin shares it, but cannot do any other operation
            api.assertApiShare(id, USER_ADMIN, SHARED_WITH_USER_NO_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertApiUpdate(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testCRUD_limitedAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

            // user has read permission on sample plugin index and has access to all sample plugin APIs except update and delete

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // cannot read admin's resource even thought it has read permission on the index because RAC feature is enabled
            api.assertApiGet(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);

            // cannot share or revoke admin's resource
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_LIMITED_ACCESS,
                SHARED_WITH_USER_LIMITED_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            api.assertApiRevoke(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // can read admin's resource once admin shares at read-only level but cannot update or delete it
            api.assertApiShare(adminResId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);

            // can no longer see admin's resource once access is revoked
            api.assertApiRevoke(adminResId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN, "");

            // can update, read and delete its own resource
            api.assertApiUpdate(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sampleUpdated");
            api.assertApiDelete(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_NOT_FOUND, "");

        }

        @Test
        public void testCRUD_fullAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            // user has * permissions

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // cannot read admin's resource even though it has read permission on the index because RAC feature is enabled
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);

            // cannot share or revoke admin's resource
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_FULL_ACCESS,
                SHARED_WITH_USER_FULL_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            api.assertApiRevoke(adminResId, SHARED_WITH_USER_FULL_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // can read admin's resource once admin shares at read-only level but cannot update or delete it
            api.assertApiShare(adminResId, USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);

            // can no longer see admin's resource once access is revoked
            api.assertApiRevoke(adminResId, USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN, "");

            // can update, read and delete its own resource
            api.assertApiUpdate(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUpdated");
            api.assertApiDelete(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_NOT_FOUND, "");
        }

        @Test
        public void testCRUD_adminCertificate() {
            String id = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            // super-admin has access to all APIs and resources
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                TestRestClient.HttpResponse resp;
                // GET single
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));
                // GET all
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.bodyAsJsonNode().get("resources").toString(), containsString("sample"));
                // UPDATE
                resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + id, "{\"name\":\"adminUpdated\"}");
                resp.assertStatusCode(HttpStatus.SC_OK);
                // DELETE
                resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }

    /**
     * Tests exercising direct raw-document operations on the index
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(Scope.NONE)
    public static class RawDocumentAccessTests extends BaseTests {

        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

        private void assertResourceIndexAccess(String id, TestSecurityConfig.User user, int expectedStatus) {
            api.assertDirectGet(id, user, expectedStatus, "");
            api.assertDirectUpdate(id, user, expectedStatus);
            api.assertDirectDelete(id, user, expectedStatus);
        }

        private void assertResourceSharingIndexAccess(String id, TestSecurityConfig.User user, int expectedStatus) {
            try (TestRestClient client = cluster.getRestClient(user)) {
                TestRestClient.HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_doc/" + id);
                resp.assertStatusCode(expectedStatus);

                // try to share with itself
                resp = client.postJson(
                    RESOURCE_SHARING_INDEX + "/_doc/" + id,
                    shareWithPayload(SHARED_WITH_USER_NO_ACCESS.getName(), sampleReadOnlyAG.name())
                );
                resp.assertStatusCode(expectedStatus);

                // delete resource sharing record
                resp = client.delete(RESOURCE_SHARING_INDEX + "/_doc/" + id);
                resp.assertStatusCode(expectedStatus);
            }
        }

        @Test
        public void testRaw_noAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_NO_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            assertResourceIndexAccess(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);

            /*
             * resource-sharing index
             * won't be allowed since user has no index permission
             */
            assertResourceSharingIndexAccess(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRaw_limitedAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            assertResourceIndexAccess(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);

            /*
             * resource-sharing index
             * won't be allowed since user has no index permission
             */
            assertResourceSharingIndexAccess(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRaw_allAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                userResId = resp.getTextFromJsonBody("/_id");
            }
            // cannot access admin's resource
            assertResourceIndexAccess(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);

            // can access own resource
            assertResourceIndexAccess(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);

            /*
             * resource-sharing index
             * will be allowed since user * index permission and system index protection is disabled
             */
            assertResourceSharingIndexAccess(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
        }

        @Test
        public void testRaw_adminCertificate() {
            String id = api.createRawResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + id, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
            }

            /*
             * resource-sharing index
             * super-admin is allowed all access
             */
            id = api.createRawResourceAs(USER_ADMIN);
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                TestRestClient.HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_doc/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);

                // try to share with itself
                resp = client.postJson(
                    RESOURCE_SHARING_INDEX + "/_doc/" + id,
                    shareWithPayload(SHARED_WITH_USER_LIMITED_ACCESS.getName(), sampleReadOnlyAG.name())
                );
                resp.assertStatusCode(HttpStatus.SC_OK);

                // delete resource sharing record
                resp = client.delete(RESOURCE_SHARING_INDEX + "/_doc/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
