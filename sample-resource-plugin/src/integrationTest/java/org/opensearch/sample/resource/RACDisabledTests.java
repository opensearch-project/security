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
import static org.opensearch.sample.resource.TestHelper.revokeAccessPayload;
import static org.opensearch.sample.resource.TestHelper.sampleAllAG;
import static org.opensearch.sample.resource.TestHelper.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing feature disabled and system index protection disabled
 * User with resource index permissions will have access to all resources via APIs and will also be able to query the resource directly
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ RACDisabledTests.ApiAccess.class, RACDisabledTests.DirectIndexAccess.class })
public class RACDisabledTests {

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
                .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, false))
                .build();
        }
    }

    /**
     * Tests exercising the plugin API endpoints
     * Users with appropriate index permissions will be able to access resources via APIs
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
     * Tests exercising direct raw-document operations on the index
     * Users with appropriate index permissions will be able to access and update resources directly
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
        }

        @Test
        public void testRawAccess_noAccessUser() {
            // user has no permissions

            // cannot access any raw request
            try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // cannot create a resource since user doesn't have indices:data/write/index permission
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // can read admin's resource
            api.assertDirectGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
            // cannot update or delete resource since user doesn't have update and delete permissions
            api.assertDirectUpdate(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            // user has * cluster and index permissions on all indices

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                userResId = resp.getTextFromJsonBody("/_id");
            }
            // can read admin's resource
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
            api.assertDirectGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUser");
            // can update and delete all resources
            api.assertDirectUpdate(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertDirectGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdated");
            api.assertDirectUpdate(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
            api.assertDirectGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdated");

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
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + adminResId).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
