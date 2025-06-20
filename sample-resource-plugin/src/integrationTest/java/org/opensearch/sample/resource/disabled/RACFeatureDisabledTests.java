/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.disabled;

import java.util.Map;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.opensearch.painless.PainlessModulePlugin;
import org.opensearch.sample.SampleResourcePlugin;
import org.opensearch.sample.resource.TestHelper;
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
import static org.opensearch.sample.resource.TestHelper.revokeAccessPayload;
import static org.opensearch.sample.resource.TestHelper.sampleAllAG;
import static org.opensearch.sample.resource.TestHelper.sampleReadOnlyAG;
import static org.opensearch.sample.resource.TestHelper.shareWithPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * These tests run with resource sharing feature disabled.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ RACFeatureDisabledTests.ApiAccessTests.class, RACFeatureDisabledTests.RawDocumentAccessTests.class })
public class RACFeatureDisabledTests {

    /**
     * Base test class providing shared cluster setup and teardown
     */
    public static abstract class BaseTests {
        @ClassRule
        public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
            .plugin(SampleResourcePlugin.class, PainlessModulePlugin.class)
            .anonymousAuth(true)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, SHARED_WITH_USER_LIMITED_ACCESS, SHARED_WITH_USER_NO_ACCESS)
            .actionGroups(sampleReadOnlyAG, sampleAllAG)
            .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, false))
            .build();

        @After
        public void clearIndices() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.delete(RESOURCE_INDEX_NAME);
            }
        }
    }

    /**
     * Tests exercising the plugin API endpoints
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
        public void testResourceSharingIndexDoesntExist() {
            api.createSampleResourceAs(USER_ADMIN);
            // when disabled, no resource-sharing index should be created
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(RESOURCE_SHARING_INDEX + "/_search");
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }
        }

        @Test
        public void testNoResourceRestrictions_noAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // cannot create own resource
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_NO_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // cannot get admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            // cannot update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");

            // feature is disabled, no handler's exist
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_NO_ACCESS,
                SHARED_WITH_USER_NO_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_BAD_REQUEST
            );
            api.assertApiRevoke(adminResId, SHARED_WITH_USER_NO_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // cannot delete admin's resource
            api.assertApiDelete(adminResId, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testNoResourceRestrictions_limitedAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sample");
            // cannot update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
            // can update own resource
            api.assertApiUpdate(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);

            // feature is disabled, no handler's exist
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_LIMITED_ACCESS,
                SHARED_WITH_USER_LIMITED_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_BAD_REQUEST
            );
            api.assertApiRevoke(
                adminResId,
                SHARED_WITH_USER_LIMITED_ACCESS,
                USER_ADMIN,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_BAD_REQUEST
            );

            // cannot delete own resource since feature is disabled
            api.assertApiDelete(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            // cannot delete admin's resource
            api.assertApiDelete(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testNoResourceRestrictions_allAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user has * cluster and index permissions

            // can create own resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sample");

            // can update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUpdated");
            // can update own resource
            api.assertApiUpdate(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUpdated");

            // feature is disabled, no handler's exist
            api.assertApiShare(
                adminResId,
                SHARED_WITH_USER_FULL_ACCESS,
                SHARED_WITH_USER_FULL_ACCESS,
                sampleReadOnlyAG.name(),
                HttpStatus.SC_BAD_REQUEST
            );
            api.assertApiRevoke(adminResId, SHARED_WITH_USER_FULL_ACCESS, USER_ADMIN, sampleReadOnlyAG.name(), HttpStatus.SC_BAD_REQUEST);

            // can delete own resource
            api.assertApiDelete(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            // can delete admin's resource
            api.assertApiDelete(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_NOT_FOUND, "");
        }

        @Test
        public void testNoResourceRestrictions_superAdmin() {
            String id = api.createSampleResourceAs(USER_ADMIN);
            // can see admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + id);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));
            }

            // can update admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                TestRestClient.HttpResponse resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + id, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));
            }

            // can't share or revoke, as handlers don't exist
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                TestRestClient.HttpResponse response = client.postJson(
                    SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + id,
                    shareWithPayload(SHARED_WITH_USER_FULL_ACCESS.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);

                response = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + id,
                    revokeAccessPayload(SHARED_WITH_USER_FULL_ACCESS.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
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
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class RawDocumentAccessTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

        @Test
        public void testRaw_noAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);

            // cannot access any raw request
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_NO_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRaw_limitedAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            // cannot create a resource since user doesn't have indices:data/write/index permission
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // can read admin's resource
            api.assertDirectGet(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sample");
            // cannot update or delete resource
            api.assertDirectUpdate(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRaw_allAccessUser() {
            String id = api.createRawResourceAs(USER_ADMIN);
            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                TestRestClient.HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_CREATED);
                userResId = resp.getTextFromJsonBody("/_id");
            }
            // can read admin's resource
            api.assertDirectGet(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertDirectGet(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUser");
            // can update admin delete all resources
            api.assertDirectUpdate(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertDirectGet(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUpdated");
            api.assertDirectUpdate(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertDirectGet(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUpdated");

            api.assertDirectDelete(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertDirectDelete(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);

            api.assertDirectGet(id, USER_ADMIN, HttpStatus.SC_NOT_FOUND, "");
            api.assertDirectGet(userResId, USER_ADMIN, HttpStatus.SC_NOT_FOUND, "");
        }

        @Test
        public void testRaw_superAdmin() {
            String id = api.createRawResourceAs(USER_ADMIN);
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + id, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
