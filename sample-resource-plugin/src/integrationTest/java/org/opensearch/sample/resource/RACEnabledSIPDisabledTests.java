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
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestHelper.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_REVOKE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.SHARED_WITH_USER_FULL_ACCESS;
import static org.opensearch.sample.resource.TestHelper.SHARED_WITH_USER_LIMITED_ACCESS;
import static org.opensearch.sample.resource.TestHelper.SHARED_WITH_USER_NO_ACCESS;
import static org.opensearch.sample.resource.TestHelper.directSharePayload;
import static org.opensearch.sample.resource.TestHelper.revokeAccessPayload;
import static org.opensearch.sample.resource.TestHelper.sampleAllAG;
import static org.opensearch.sample.resource.TestHelper.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing feature enabled and system index protection enabled
 * Only users with appropriate access to resources will be allowed via APIs and via direct index access since SIP is disabled.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ RACEnabledSIPDisabledTests.ApiAccessTests.class, RACEnabledSIPDisabledTests.DirectIndexAccessTests.class })
public class RACEnabledSIPDisabledTests {

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

            // user has no permission

            // cannot create own resource
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_NO_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // cannot get admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            // cannot update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");

            // cannot share admin's resource with itself
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_NO_ACCESS,
                SHARED_WITH_USER_NO_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            api.assertApiRevoke(adminResId, SHARED_WITH_USER_NO_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // cannot delete admin's resource
            api.assertApiDelete(adminResId, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testApiAccess_limitedAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // cannot see admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiGetAll(SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sampleUser"); // can only see own resource

            // cannot update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
            // can update own resource
            api.assertApiUpdate(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK);

            // cannot share or revoke admin's resource
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_LIMITED_ACCESS,
                SHARED_WITH_USER_LIMITED_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            api.assertApiRevoke(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // can share or revoke own resource
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiShare(userResId, SHARED_WITH_USER_LIMITED_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sampleUpdated");
            api.assertApiRevoke(userResId, SHARED_WITH_USER_LIMITED_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");

            // can delete own resource since user is the owner
            api.assertApiDelete(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK);
            // cannot delete admin's resource
            api.assertApiDelete(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testApiAccess_allAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

            // user has * cluster and index permissions

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // cannot see admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN, "sample");
            api.assertApiGetAll(SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUser");

            // cannot update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
            // can update own resource
            api.assertApiUpdate(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUpdated");

            // cannot share or revoke admin's resource
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_FULL_ACCESS,
                SHARED_WITH_USER_FULL_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            api.assertApiRevoke(adminResId, SHARED_WITH_USER_FULL_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_FORBIDDEN);

            // can share or revoke own resource
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiShare(userResId, SHARED_WITH_USER_FULL_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sampleUpdated");
            api.assertApiRevoke(userResId, SHARED_WITH_USER_FULL_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");

            // can delete own resource
            api.assertApiDelete(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            // cannot delete admin's resource
            api.assertApiDelete(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
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
                    shareWithPayload(SHARED_WITH_USER_NO_ACCESS.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_OK);

                response = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + id,
                    revokeAccessPayload(SHARED_WITH_USER_NO_ACCESS.getName(), sampleAllAG.name())
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
     * Tests exercising direct raw-document operations on the index
     * Users with permission to resource and its sharing index will be able to interact with them successfully.
     *
     * Shows importance of System-Index protection feature for this new authz mechanism, by showing what would happen if SIP is disabled but feature is enabled.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class DirectIndexAccessTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

        @Test
        public void testRawAccess_noAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
            // user has no permission

            // cannot access any raw request
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_NO_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);

            // cannot interact with resource sharing index
            api.assertDirectViewSharingRecord(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectShare(id, SHARED_WITH_USER_NO_ACCESS, SHARED_WITH_USER_NO_ACCESS, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectRevoke(id, SHARED_WITH_USER_NO_ACCESS, SHARED_WITH_USER_NO_ACCESS, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertDirectDeleteResourceSharingRecord(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

            // user has read permission on resource index

            // cannot create a resource since user doesn't have indices:data/write/index permission
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // cannot read admin's resource directly since system index protection is enabled
            api.assertDirectGet(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            // once admin share's record, user can then query it directly
            api.assertDirectShare(id, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertDirectGet(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sample");

            // cannot update or delete resource
            api.assertDirectUpdate(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);

            // cannot access resource sharing index since user doesn't have permissions on that index
            api.assertDirectViewSharingRecord(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectShare(
                id,
                SHARED_WITH_USER_LIMITED_ACCESS,
                SHARED_WITH_USER_LIMITED_ACCESS,
                sampleAllAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            api.assertDirectRevoke(
                id,
                SHARED_WITH_USER_LIMITED_ACCESS,
                SHARED_WITH_USER_LIMITED_ACCESS,
                sampleAllAG.name(),
                HttpStatus.SC_FORBIDDEN
            );
            api.assertDirectDeleteResourceSharingRecord(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            api.awaitSharingEntry();

            // user has * permission on all indices

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                userResId = resp.getTextFromJsonBody("/_id");
            }
            // cannot read admin's resource directly since resource is not shared with them
            api.assertDirectGet(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            // once admin share's record, user can then query it directly
            api.assertDirectShare(id, USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertDirectGet(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sample");

            // admin cannot read user's resource until after they share it with admin
            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectShare(userResId, SHARED_WITH_USER_FULL_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sample");

            // cannot update or delete resource
            api.assertDirectUpdate(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
            // can update and delete own resource
            api.assertDirectUpdate(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertDirectDelete(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);

            // can view, share, revoke and delete resource sharing record(s) directly
            api.assertDirectViewSharingRecord(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertDirectShare(id, SHARED_WITH_USER_FULL_ACCESS, SHARED_WITH_USER_NO_ACCESS, sampleAllAG.name(), HttpStatus.SC_OK);
            api.assertDirectRevoke(id, SHARED_WITH_USER_FULL_ACCESS, SHARED_WITH_USER_NO_ACCESS, sampleAllAG.name(), HttpStatus.SC_OK);
            api.assertDirectDeleteResourceSharingRecord(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
        }

        @Test
        public void testRawAccess_superAdmin() {
            String id = api.createRawResourceAs(USER_ADMIN);
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
                    directSharePayload(id, USER_ADMIN.getName(), SHARED_WITH_USER_NO_ACCESS.getName(), sampleReadOnlyAG.name())
                ).assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_SHARING_INDEX + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);

                // can delete resource
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
