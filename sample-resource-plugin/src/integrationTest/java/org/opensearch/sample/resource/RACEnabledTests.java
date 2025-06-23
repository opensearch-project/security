/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
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
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestHelper.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestHelper.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestHelper.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestHelper.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_REVOKE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.directSharePayload;
import static org.opensearch.sample.resource.TestHelper.revokeAccessPayload;
import static org.opensearch.sample.resource.TestHelper.sampleAllAG;
import static org.opensearch.sample.resource.TestHelper.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing feature enabled and system index protection enabled
 * This is how the feature is intended to be utilized.
 * Only user's with appropriate permissions be able to access a resource. SIP prevents any direct index accesses.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ RACEnabledTests.ApiAccessTests.class, RACEnabledTests.DirectIndexAccessTests.class })
public class RACEnabledTests {

    /**
     * Base test class providing shared cluster setup and teardown
     */
    public static abstract class BaseTests {
        @ClassRule
        public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
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
            .plugin(PainlessModulePlugin.class)
            .anonymousAuth(true)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER_ADMIN, FULL_ACCESS_USER, LIMITED_ACCESS_USER, NO_ACCESS_USER)
            .actionGroups(sampleReadOnlyAG, sampleAllAG)
            .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, true, SECURITY_SYSTEM_INDICES_ENABLED_KEY, true))
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
     * with feature enabled user's cannot modify resource that is not shared with them
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class ApiAccessTests extends BaseTests {

        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

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
            api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_search");
                resp.assertStatusCode(HttpStatus.SC_OK);
            }
        }

        @Test
        public void testApiAccess_noAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

            // user has no permission

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

            // cannot share admin's resource with itself
            api.assertApiShare(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(adminResId, NO_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // cannot delete admin's resource
            api.assertApiDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testApiAccess_limitedAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

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

            // cannot see admin's resource
            api.assertApiGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiGetAll(LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sampleUser"); // can only see own resource

            // cannot update admin's resource
            api.assertApiUpdate(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
            // can update own resource
            api.assertApiUpdate(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK);

            // cannot share or revoke admin's resource
            api.assertApiShare(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(adminResId, LIMITED_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // can share or revoke own resource
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiShare(userResId, LIMITED_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sampleUpdated");
            api.assertApiRevoke(userResId, LIMITED_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");

            // can delete own resource since user is the owner
            api.assertApiDelete(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK);
            // cannot delete admin's resource
            api.assertApiDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testApiAccess_allAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

            // user has * cluster and index permissions

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // cannot see admin's resource
            api.assertApiGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "sample");
            api.assertApiGetAll(FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUser");

            // cannot update admin's resource
            api.assertApiUpdate(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            // can update own resource
            api.assertApiUpdate(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertApiGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdated");

            // cannot share or revoke admin's resource
            api.assertApiShare(adminResId, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(adminResId, FULL_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // can share or revoke own resource
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiShare(userResId, FULL_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sampleUpdated");
            api.assertApiRevoke(userResId, FULL_ACCESS_USER, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");

            // can delete own resource
            api.assertApiDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            // cannot delete admin's resource
            api.assertApiDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testApiAccess_superAdmin() {
            String id = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            // can see admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));
            }

            // can update admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                HttpResponse resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + id, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));
            }

            // can share and revoke admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse response = client.postJson(
                    SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + id,
                    shareWithPayload(NO_ACCESS_USER.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_OK);

                response = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + id,
                    revokeAccessPayload(NO_ACCESS_USER.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_OK);
            }

            // can delete admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }

        }
    }

    /**
     * Tests exercising direct raw-document operations on the index.
     * Only super-admins will be able to perform raw access requet
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class DirectIndexAccessTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

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

        @Test
        public void testRawAccess_noAccessUser() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            api.awaitSharingEntry();
            // user has no permission
            assertResourceIndexAccess(id, NO_ACCESS_USER);
            assertResourceSharingIndexAccess(id, NO_ACCESS_USER);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            api.awaitSharingEntry();
            // user has read permission on resource index
            // since SIP is enabled, user will not be able to perform any raw requests

            assertResourceIndexAccess(id, LIMITED_ACCESS_USER);
            assertResourceSharingIndexAccess(id, LIMITED_ACCESS_USER);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            // user has * permission on all indices
            // since SIP is enabled, user will not be able to perform any raw requests

            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            api.awaitSharingEntry();
            assertResourceIndexAccess(id, FULL_ACCESS_USER);

            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(id, FULL_ACCESS_USER, HttpStatus.SC_NOT_FOUND);
            api.assertDirectShare(id, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectRevoke(id, FULL_ACCESS_USER, FULL_ACCESS_USER, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectDeleteResourceSharingRecord(id, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_superAdmin() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            api.awaitSharingEntry();
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
}
