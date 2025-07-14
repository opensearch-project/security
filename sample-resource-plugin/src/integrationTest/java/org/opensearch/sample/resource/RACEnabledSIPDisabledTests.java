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
import org.junit.Before;
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
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing feature enabled and system index protection enabled
 * Only users with appropriate access to resources will be allowed via APIs and via direct index access since SIP is disabled.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ RACEnabledSIPDisabledTests.ApiAccess.class, RACEnabledSIPDisabledTests.DirectIndexAccess.class })
public class RACEnabledSIPDisabledTests {

    /**
     * Base test class providing shared cluster setup and teardown
     */
    static abstract class Base {
        static LocalCluster newCluster() {

            return new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
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
                .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
                .build();
        }
    }

    /**
     * Tests exercising the plugin API endpoints
     * with feature enabled user's cannot modify resource that is not shared with them
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class ApiAccess extends Base {

        @ClassRule
        public static LocalCluster cluster = newCluster();

        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

        private String adminResId;

        @Before
        public void setup() {
            adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(); // wait until sharing entry is created
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
        public void testApiAccess_noAccessUser() {
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
            // can see admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));
            }

            // can update admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                HttpResponse resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));
            }

            // can share and revoke admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse response = client.postJson(
                    SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + adminResId,
                    shareWithPayload(NO_ACCESS_USER.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_OK);

                response = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + adminResId,
                    revokeAccessPayload(NO_ACCESS_USER.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_OK);
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
     * Tests exercising direct raw-document operations on the index
     * Users with permission to resource and its sharing index will be able to interact with them successfully.
     * Shows the importance of System-Index protection feature for this new authz mechanism, by showing what would happen if SIP is disabled and the feature is enabled.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class DirectIndexAccess extends Base {

        @ClassRule
        public static LocalCluster cluster = newCluster();

        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

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
