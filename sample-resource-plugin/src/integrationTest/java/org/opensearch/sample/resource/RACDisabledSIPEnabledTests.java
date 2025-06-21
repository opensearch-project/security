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
 * These tests run with resource sharing feature disabled but system index enabled.
 * User with resource index permissions will have access to all resources via plugin APIs but not through direct index access requests
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ RACDisabledSIPEnabledTests.ApiAccessTests.class, RACDisabledSIPEnabledTests.DirectIndexAccessTests.class })
public class RACDisabledSIPEnabledTests {

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
            .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, false, SECURITY_SYSTEM_INDICES_ENABLED_KEY, true))
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
     * All users can access all resources through the plugin APIs given they have appropriate index permission
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
        public void testApiAccess_limitedAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_OK, "sample");
            // cannot update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
            // cannot update own resource
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

            // cannot delete resource since feature is disabled and user doesn't have delete permission
            api.assertApiDelete(userResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            // cannot delete admin's resource since user doesn't have delete permission
            api.assertApiDelete(adminResId, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertApiGet(adminResId, USER_ADMIN, HttpStatus.SC_OK, "sample");
        }

        @Test
        public void testApiAccess_allAccessUser() {
            String adminResId = api.createSampleResourceAs(USER_ADMIN);

            // user has * cluster and * index permissions on all indices

            // can create a resource
            String userResId;
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sample);
                resp.assertStatusCode(HttpStatus.SC_OK);
                userResId = resp.getTextFromJsonBody("/message").split(":")[1].trim();
            }

            // can see admin's resource
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sample");
            api.assertApiGetAll(SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sample");

            // can update admin's resource
            api.assertApiUpdate(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            api.assertApiGet(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK, "sampleUpdated");
            // can update a resource
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

            // can delete a resource
            api.assertApiDelete(userResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
            // can delete admin's resource
            api.assertApiDelete(adminResId, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_OK);
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
                    shareWithPayload(SHARED_WITH_USER_FULL_ACCESS.getName(), sampleAllAG.name())
                );
                resp.assertStatusCode(HttpStatus.SC_BAD_REQUEST);

                resp = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + id,
                    revokeAccessPayload(SHARED_WITH_USER_FULL_ACCESS.getName(), sampleAllAG.name())
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

    /**
     * Tests exercising direct raw-document operations on the index
     * No user except super-admin ca access documents directly since system index protection is enabled
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class DirectIndexAccessTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);

        @Test
        public void testRawAccess_noAccessUser() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());

            // user has no permissions

            // cannot access any raw request
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_NO_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            api.assertDirectGet(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectGetAll(SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN, "");
            api.assertDirectUpdate(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_NO_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_limitedAccessUser() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            // user doesn't have update or delete permissions, but can read and create
            // Has * permission on sample plugin resource index

            // cannot create a resource since user doesn't have indices:data/write/index permission
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_LIMITED_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // cannot read admin's resource since system index protection is enabled, will show 404
            api.assertDirectGet(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_NOT_FOUND, "");
            // cannot update or delete resource
            api.assertDirectUpdate(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_LIMITED_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_allAccessUser() {
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            // user has * cluster and index permissions on all indices

            // cannot create a resource directly since system index protection (SIP) is enabled
            try (TestRestClient client = cluster.getRestClient(SHARED_WITH_USER_FULL_ACCESS)) {
                String sample = "{\"name\":\"sampleUser\"}";
                HttpResponse resp = client.postJson(RESOURCE_INDEX_NAME + "/_doc", sample);
                resp.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
            // cannot read admin's resource directly since SIP is enabled
            api.assertDirectGet(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_NOT_FOUND, "sample");
            // cannot update or delete admin resource directly since SIP is enabled
            api.assertDirectUpdate(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
            api.assertDirectDelete(id, SHARED_WITH_USER_FULL_ACCESS, HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void testRawAccess_adminCertificateUser() {
            // super-admin can perform any operation
            String id = api.createRawResourceAs(cluster.getAdminCertificate());
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.get(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
                client.postJson(RESOURCE_INDEX_NAME + "/_doc/" + id, "{\"name\":\"adminDirectUpdated\"}")
                    .assertStatusCode(HttpStatus.SC_OK);
                client.delete(RESOURCE_INDEX_NAME + "/_doc/" + id).assertStatusCode(HttpStatus.SC_OK);
            }
        }
    }
}
