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
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
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
import static org.opensearch.security.resources.ResourceSharingIndexHandler.getSharingIndex;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access on multiple sharing levels.
 * Shared_with entities must at-least possess cluster-perms access to the APIs to be able to access the resource.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    MultiAccessLevelsTests.AdminCertificateAccessTests.class,
    MultiAccessLevelsTests.ReadOnlyAccessTests.class,
    MultiAccessLevelsTests.FullAccessTests.class,
    MultiAccessLevelsTests.MixedAccessTests.class })
public class MultiAccessLevelsTests {

    private static final String RESOURCE_SHARING_INDEX = getSharingIndex(RESOURCE_INDEX_NAME);

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
            .nodeSettings(Map.of(SECURITY_SYSTEM_INDICES_ENABLED_KEY, true, OPENSEARCH_RESOURCE_SHARING_ENABLED, true))
            .build();

        @After
        public void cleanup() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.delete(RESOURCE_INDEX_NAME);
                client.delete(RESOURCE_SHARING_INDEX);
            }
        }

    }

    /**
     * Asserts admin certificate permissions
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class AdminCertificateAccessTests extends BaseTests {

        @Test
        public void adminCertificate_canCRUD() {
            TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);
            String resourceId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(); // wait until sharing entry is created
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sample"));
            }

            // can update admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                String updatePayload = "{" + "\"name\": \"sampleUpdated\"" + "}";
                HttpResponse resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + resourceId, updatePayload);
                resp.assertStatusCode(HttpStatus.SC_OK);
                assertThat(resp.getBody(), containsString("sampleUpdated"));
            }

            // can share and revoke admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse response = client.postJson(
                    SAMPLE_RESOURCE_SHARE_ENDPOINT + "/" + resourceId,
                    shareWithPayload(SHARED_WITH_USER_NO_ACCESS.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_OK);

                response = client.postJson(
                    SAMPLE_RESOURCE_REVOKE_ENDPOINT + "/" + resourceId,
                    revokeAccessPayload(SHARED_WITH_USER_NO_ACCESS.getName(), sampleAllAG.name())
                );

                response.assertStatusCode(HttpStatus.SC_OK);
            }

            // can delete admin's resource
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                HttpResponse resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + resourceId);
                resp.assertStatusCode(HttpStatus.SC_OK);
                resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId);
                resp.assertStatusCode(HttpStatus.SC_NOT_FOUND);
            }
        }
    }

    /**
     * Test resource access to a resource shared with read-only access-level.
     * All tests are against USER_ADMIN's resource created during setup.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class ReadOnlyAccessTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);
        private String resourceId;

        @Before
        public void setup() {
            resourceId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(); // wait until sharing entry is created
        }

        @After
        public void cleanup() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.delete(RESOURCE_INDEX_NAME);
                client.delete(RESOURCE_SHARING_INDEX);
            }
        }

        private void assertNoAccessBeforeSharing(TestSecurityConfig.User user) {
            api.assertApiGet(resourceId, user, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiUpdate(resourceId, user, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

            api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
        }

        private void assertReadOnly(TestSecurityConfig.User user) {
            api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
            api.assertApiUpdate(resourceId, user, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

            api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
        }

        @Test
        public void fullAccessUser_canRead_cannotUpdateDeleteShareRevoke() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_FULL_ACCESS);
            // share at sampleReadOnly level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(); // wait until sharing info is populated
            assertReadOnly(SHARED_WITH_USER_FULL_ACCESS);
        }

        @Test
        public void limitedAccessUser_canRead_cannotUpdateDeleteShareRevoke() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_LIMITED_ACCESS);
            // share at sampleReadOnly level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(); // wait until sharing info is populated
            assertReadOnly(SHARED_WITH_USER_LIMITED_ACCESS);
        }

        @Test
        public void noAccessUser_canRead_cannotUpdateDeleteShareRevoke() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_NO_ACCESS);
            // share at sampleReadOnly level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_NO_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(); // wait until sharing info is populated
            assertReadOnly(SHARED_WITH_USER_NO_ACCESS);
        }
    }

    /**
     * Test resource access to a resource shared with full permissions access-level.
     * All tests are against USER_ADMIN's resource created during setup.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class FullAccessTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);
        private String resourceId;

        @Before
        public void setup() {
            resourceId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(); // wait until sharing entry is created
        }

        private void assertNoAccessBeforeSharing(TestSecurityConfig.User user) {
            api.assertApiGet(resourceId, user, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiUpdate(resourceId, user, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

            api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
        }

        private void assertFullAccess(TestSecurityConfig.User user) {
            api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
            api.assertApiUpdate(resourceId, user, HttpStatus.SC_OK);
            api.assertApiDelete(resourceId, user, HttpStatus.SC_OK);
        }

        // check that target can not access before sharing and after revoking
        // while resource is shared they can access it and share it someone else
        private void assertSharingAccess(TestSecurityConfig.User user, TestSecurityConfig.User target) {
            api.assertApiGet(resourceId, target, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiShare(resourceId, user, target, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry();

            api.assertApiGet(resourceId, target, HttpStatus.SC_OK, "sample");
            api.assertApiShare(resourceId, target, new TestSecurityConfig.User("test"), sampleAllAG.name(), HttpStatus.SC_OK);

            api.assertApiRevoke(resourceId, user, target, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry();
            api.assertApiGet(resourceId, target, HttpStatus.SC_FORBIDDEN, "");
        }

        @Test
        public void fullAccessUser_canCRUD() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_FULL_ACCESS);
            // share at sampleAllAG level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(); // wait until sharing info is populated

            // can share admin's resource with others since full access was granted
            assertSharingAccess(SHARED_WITH_USER_FULL_ACCESS, SHARED_WITH_USER_LIMITED_ACCESS);

            assertFullAccess(SHARED_WITH_USER_FULL_ACCESS);
        }

        @Test
        public void limitedAccessUser_canCRUD() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_LIMITED_ACCESS);
            // share at sampleAllAG level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(); // wait until sharing info is populated

            assertSharingAccess(SHARED_WITH_USER_LIMITED_ACCESS, SHARED_WITH_USER_FULL_ACCESS);

            assertFullAccess(SHARED_WITH_USER_LIMITED_ACCESS);
        }

        @Test
        public void noAccessUser_canCRUD() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_NO_ACCESS);
            // share at sampleAllAG level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_NO_ACCESS, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry(); // wait until sharing info is populated

            assertSharingAccess(SHARED_WITH_USER_NO_ACCESS, SHARED_WITH_USER_LIMITED_ACCESS);

            assertFullAccess(SHARED_WITH_USER_NO_ACCESS);
        }
    }

    /**
     * Test resource access to a resource shared with full permissions access-level.
     * All tests are against USER_ADMIN's resource created during setup.
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class MixedAccessTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);
        private String resourceId;

        @Before
        public void setup() {
            resourceId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(); // wait until sharing entry is created
        }

        private void assertNoAccessBeforeSharing(TestSecurityConfig.User user) {
            api.assertApiGet(resourceId, user, HttpStatus.SC_FORBIDDEN, "");
            api.assertApiUpdate(resourceId, user, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

            api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
        }

        private void assertReadOnly(TestSecurityConfig.User user) {
            api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
            api.assertApiUpdate(resourceId, user, HttpStatus.SC_FORBIDDEN);
            api.assertApiDelete(resourceId, user, HttpStatus.SC_FORBIDDEN);

            api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
            api.assertApiRevoke(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_FORBIDDEN);
        }

        private void assertFullAccess(TestSecurityConfig.User user) {
            api.assertApiGet(resourceId, user, HttpStatus.SC_OK, "sample");
            api.assertApiUpdate(resourceId, user, HttpStatus.SC_OK);
            api.assertApiShare(resourceId, user, user, sampleAllAG.name(), HttpStatus.SC_OK);
            api.assertApiRevoke(resourceId, user, USER_ADMIN, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry();
            api.assertApiDelete(resourceId, user, HttpStatus.SC_OK);
        }

        @Test
        public void multipleUsers_multipleLevels() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_FULL_ACCESS);
            assertNoAccessBeforeSharing(SHARED_WITH_USER_LIMITED_ACCESS);
            // 1. share at read-only for full-access user & at full-access for limited perms user
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry();

            // 2. check individual access
            assertReadOnly(SHARED_WITH_USER_FULL_ACCESS);

            // 3. limited access user shares with full-access user at sampleAllAG
            api.assertApiShare(
                resourceId,
                SHARED_WITH_USER_LIMITED_ACCESS,
                SHARED_WITH_USER_FULL_ACCESS,
                sampleAllAG.name(),
                HttpStatus.SC_OK
            );
            api.awaitSharingEntry();

            // 4. full-access user now has full-access to admin's resource
            assertFullAccess(SHARED_WITH_USER_FULL_ACCESS);
        }

        @Test
        public void multipleUsers_sameLevel() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_FULL_ACCESS);
            assertNoAccessBeforeSharing(SHARED_WITH_USER_LIMITED_ACCESS);

            // 1. share with both users at read-only level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_FULL_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry();

            // 2. assert both now have read-only access
            assertReadOnly(SHARED_WITH_USER_LIMITED_ACCESS);
        }

        @Test
        public void sameUser_multipleLevels() {
            assertNoAccessBeforeSharing(SHARED_WITH_USER_LIMITED_ACCESS);

            // 1. share with user at read-only level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleReadOnlyAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry();

            // 2. assert user now have read-only access
            assertReadOnly(SHARED_WITH_USER_LIMITED_ACCESS);

            // 3. share with user at full-access level
            api.assertApiShare(resourceId, USER_ADMIN, SHARED_WITH_USER_LIMITED_ACCESS, sampleAllAG.name(), HttpStatus.SC_OK);
            api.awaitSharingEntry();

            // 4. assert user now has full access
            assertFullAccess(SHARED_WITH_USER_LIMITED_ACCESS);
        }
    }
}
