/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchAllPayload;
import static org.opensearch.sample.resource.TestUtils.ApiHelper.searchByNamePayload;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_MIGRATION_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_CREATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_SEARCH_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.migrationPayload_valid;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.putSharingInfoPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;
import static org.awaitility.Awaitility.await;

/**
 * Verifies dynamic behavior of cluster setting:
 * {@link ConfigConstants#OPENSEARCH_RESOURCE_SHARING_ENABLED}
 *
 * Phase 1: feature disabled
 * Phase 2: flip setting via _cluster/settings and verify enabled behavior
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FeatureFlagSettingTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(false, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String adminResId;

    // --------- Lifecycle ---------

    @Before
    public void setup() {
        // Starting with disabled for deterministic ordering
        setResourceSharingEnabled(false);
        awaitResourceSharingEnabled(false);

        adminResId = createSampleResourceAs(USER_ADMIN);
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
        // Flip the dynamic cluster setting to false
        setResourceSharingEnabled(false);
        awaitResourceSharingEnabled(false);
    }

    private String createSampleResourceAs(TestSecurityConfig.User user) {
        try (TestRestClient client = cluster.getRestClient(user)) {
            String sampleResource = """
                {
                    "name":"sample",
                    "store_user": true
                }
                """;

            TestRestClient.HttpResponse response = client.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, sampleResource);

            String resourceId = response.getTextFromJsonBody("/message").split(":")[1].trim();

            Awaitility.await()
                .alias("Wait until resource data is populated")
                .until(() -> client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + resourceId).getStatusCode(), equalTo(200));
            return resourceId;
        }
    }

    // --------- Phase 1: Disabled behavior ---------

    @Test
    public void testBehaviorWhenDisabled() {
        // “Disabled” expectations:
        // - Share api handler not exist -> 501 on endpoints that would be implemented by the feature
        // - Access relies purely on existing index/cluster perms ("legacy" RBAC behavior)

        assertNoAccessUser_Disabled();
        assertLimitedUser_Disabled();
        assertFullUser_Disabled();
        assertAdminCert_Disabled();
    }

    // --------- Assertions: Disabled behavior ---------

    private void assertNoAccessUser_Disabled() {
        // cannot create
        try (TestRestClient c = cluster.getRestClient(NO_ACCESS_USER)) {
            TestRestClient.HttpResponse r = c.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, "{\"name\":\"sampleUser\"}");
            r.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }
        // cannot get, update, delete
        api.assertApiGet(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiUpdate(adminResId, NO_ACCESS_USER, "x", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        // share/revoke endpoints exist? -> when disabled we expect 403 (no perm) or 501 (no handler).
        api.assertApiShare(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_NOT_IMPLEMENTED);
        api.assertApiRevoke(adminResId, NO_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_NOT_IMPLEMENTED);

        // search forbidden
        api.assertApiGetSearchForbidden(NO_ACCESS_USER);
        api.assertApiPostSearchForbidden(searchAllPayload(), NO_ACCESS_USER);
        api.assertApiPostSearchForbidden(searchByNamePayload("sample"), NO_ACCESS_USER);
    }

    private void assertLimitedUser_Disabled() {
        // create own
        String userResId = createSampleResourceAs(LIMITED_ACCESS_USER);

        // see admin resource (disabled path follows index perms) per your “disabled” expectations
        api.assertApiGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
        api.assertApiGetAll(LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");

        // cannot update (no perm); cannot delete
        api.assertApiUpdate(adminResId, LIMITED_ACCESS_USER, "x", HttpStatus.SC_FORBIDDEN);
        api.assertApiUpdate(userResId, LIMITED_ACCESS_USER, "x", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

        // share/revoke should be NOT IMPLEMENTED when disabled (your “last 4 tests”)
        api.assertApiShare(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_NOT_IMPLEMENTED);
        api.assertApiRevoke(adminResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_NOT_IMPLEMENTED);

        // can search both resources
        api.assertApiGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 2, "sample");
        api.assertApiPostSearch(searchAllPayload(), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 2, "sample");
        api.assertApiPostSearch(searchByNamePayload("sample"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 2, "sample");
    }

    private void assertFullUser_Disabled() {
        String userResId = createSampleResourceAs(FULL_ACCESS_USER);

        // full * perms when disabled -> can see & update both
        api.assertApiGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
        api.assertApiGetAll(FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(adminResId, FULL_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_OK);
        api.assertApiUpdate(userResId, FULL_ACCESS_USER, "sampleUpdateUser", HttpStatus.SC_OK);

        // share/revoke not implemented
        api.assertApiShare(adminResId, FULL_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_NOT_IMPLEMENTED);
        api.assertApiRevoke(adminResId, FULL_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_NOT_IMPLEMENTED);

        // search sees both
        api.assertApiGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 3, "sampleUpdateAdmin"); // admin + full user + limited user created
                                                                                            // above
        api.assertApiPostSearch(searchAllPayload(), FULL_ACCESS_USER, HttpStatus.SC_OK, 3, "sampleUpdateAdmin");
        api.assertApiPostSearch(searchByNamePayload("sampleUpdateAdmin"), FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateAdmin");
        api.assertApiPostSearch(searchByNamePayload("sampleUpdateUser"), FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");

        // can delete both
        api.assertApiDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
        api.assertApiDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
    }

    private void assertAdminCert_Disabled() {
        adminResId = createSampleResourceAs(USER_ADMIN);
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // read / update ok
            TestRestClient.HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
            resp.assertStatusCode(HttpStatus.SC_OK);

            resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId, "{\"name\":\"sampleUpdated\"}");
            resp.assertStatusCode(HttpStatus.SC_OK);

            // share/revoke not implemented
            resp = client.putJson(
                SECURITY_SHARE_ENDPOINT,
                putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
            );
            resp.assertStatusCode(HttpStatus.SC_NOT_IMPLEMENTED);

            TestUtils.PatchSharingInfoPayloadBuilder payloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
            payloadBuilder.resourceId(adminResId);
            payloadBuilder.resourceType(RESOURCE_TYPE);
            payloadBuilder.revoke(new Recipients(Map.of(Recipient.USERS, Set.of(FULL_ACCESS_USER.getName()))), SAMPLE_FULL_ACCESS);
            resp = client.patch(SECURITY_SHARE_ENDPOINT, payloadBuilder.build());
            resp.assertStatusCode(HttpStatus.SC_NOT_IMPLEMENTED);

            // search works
            resp = client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT);
            resp.assertStatusCode(HttpStatus.SC_OK);

            // delete ok
            resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + adminResId);
            resp.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    // --------- Phase 2: Flip to Enabled then verify enabled behavior ---------

    @Test
    public void testBehaviorAfterEnabling() {
        // Flip the dynamic cluster setting to true
        setResourceSharingEnabled(true);
        awaitResourceSharingEnabled(true);

        // migrate existing resources to new records
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse migrateResponse = client.postJson(RESOURCE_SHARING_MIGRATION_ENDPOINT, migrationPayload_valid());
            migrateResponse.assertStatusCode(HttpStatus.SC_OK);
            assertThat(migrateResponse.bodyAsMap().get("summary"), equalTo("Migration complete. migrated 1; skippedNoUser 0; failed 0"));
        }

        // “Enabled” expectations:
        // - Share/Revoke handlers exist -> return permission-based 200/403 (not 501)
        // - Search and read access follow resource-sharing rules
        // - Owners can share/revoke; others constrained

        assertNoAccessUser_Enabled();
        assertLimitedUser_Enabled();
        assertFullUser_Enabled();
        assertAdminCert_Enabled();
    }

    // --------- Helpers: cluster setting flips & awaits ---------
    private void setResourceSharingEnabled(boolean enabled) {
        String body = String.format("{\"transient\":{\"%s\":%s}}", ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED, enabled);
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse resp = client.putJson("_cluster/settings", body);
            resp.assertStatusCode(HttpStatus.SC_OK);
        }
    }

    /**
     * Confirm the setting took effect
     */
    private void awaitResourceSharingEnabled(boolean expected) {
        // Wait for cluster setting to reflect desired value
        await().atMost(30, TimeUnit.SECONDS).pollInterval(200, TimeUnit.MILLISECONDS).until(() -> readSettingEquals(expected));
    }

    private boolean readSettingEquals(boolean expected) {
        try (var client = cluster.getRestClient(cluster.getAdminCertificate())) {
            var r = client.get("_cluster/settings?include_defaults=true&flat_settings=true");
            r.assertStatusCode(200);
            String key = "\"" + ConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED + "\":\"" + expected + "\"";
            return r.getBody().contains(key);
        } catch (Exception e) {
            return false;
        }
    }

    // --------- Assertions: Enabled behavior ---------

    private void assertNoAccessUser_Enabled() {
        // cannot create
        try (TestRestClient c = cluster.getRestClient(NO_ACCESS_USER)) {
            TestRestClient.HttpResponse r = c.putJson(SAMPLE_RESOURCE_CREATE_ENDPOINT, "{\"name\":\"sampleUser\"}");
            r.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        }
        // cannot get/update/delete
        api.assertApiGet(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiUpdate(adminResId, NO_ACCESS_USER, "x", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(adminResId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);

        // share/revoke forbidden (handlers now exist → 403 vs 501)
        api.assertApiShare(adminResId, NO_ACCESS_USER, NO_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(adminResId, NO_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_FORBIDDEN);

        // search forbidden
        api.assertApiGetSearchForbidden(NO_ACCESS_USER);
        api.assertApiPostSearchForbidden(searchAllPayload(), NO_ACCESS_USER);
        api.assertApiPostSearchForbidden(searchByNamePayload("sample"), NO_ACCESS_USER);
    }

    private void assertLimitedUser_Enabled() {
        String userResId = createSampleResourceAs(LIMITED_ACCESS_USER);

        // cannot see admin resource under sharing rules
        api.assertApiGet(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiGetAll(LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");

        // can update own; not others
        api.assertApiUpdate(adminResId, LIMITED_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiUpdate(userResId, LIMITED_ACCESS_USER, "sampleUpdateUser", HttpStatus.SC_OK);
        api.assertApiGet(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdateUser");
        api.assertApiGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");

        // cannot share/revoke others, can share own
        api.assertApiShare(adminResId, LIMITED_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(adminResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_FORBIDDEN);

        api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiShare(userResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_OK);
        api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_OK, "sampleUpdateUser");
        api.assertApiRevoke(userResId, LIMITED_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_OK);
        api.assertApiGet(userResId, USER_ADMIN, HttpStatus.SC_FORBIDDEN, "");

        // searches aligned with ownership
        api.assertApiGetSearch(LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");
        api.assertApiPostSearch(searchAllPayload(), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");
        api.assertApiPostSearch(searchByNamePayload("sample"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 0, "");
        api.assertApiPostSearch(searchByNamePayload("sampleUpdateUser"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");

        // can delete own
        api.assertApiDelete(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK);
        // cannot delete admin's
        api.assertApiDelete(adminResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
    }

    private void assertFullUser_Enabled() {
        String userResId = createSampleResourceAs(FULL_ACCESS_USER);

        // even with * perms, sharing rules restrict access to others’ resources
        api.assertApiGet(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "sample");
        api.assertApiGetAll(FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");

        // can update own
        api.assertApiUpdate(adminResId, FULL_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiUpdate(userResId, FULL_ACCESS_USER, "sampleUpdateUser", HttpStatus.SC_OK);
        api.assertApiGet(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdateUser");
        api.assertApiGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");

        // cannot share/revoke others’ resources; can share own
        api.assertApiShare(adminResId, FULL_ACCESS_USER, FULL_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_FORBIDDEN);
        api.assertApiRevoke(adminResId, FULL_ACCESS_USER, USER_ADMIN, SAMPLE_READ_ONLY, HttpStatus.SC_FORBIDDEN);

        api.assertApiGet(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiShare(userResId, FULL_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_OK);
        api.assertApiGet(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sampleUpdateUser");
        api.assertApiPostSearch(searchByNamePayload("sampleUpdateUser"), LIMITED_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");
        api.assertApiRevoke(userResId, FULL_ACCESS_USER, LIMITED_ACCESS_USER, SAMPLE_READ_ONLY, HttpStatus.SC_OK);
        api.assertApiGet(userResId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");

        // search visibility matches sharing state
        api.assertApiGetSearch(FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");
        api.assertApiPostSearch(searchAllPayload(), FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");
        api.assertApiPostSearch(searchByNamePayload("sample"), FULL_ACCESS_USER, HttpStatus.SC_OK, 0, "");
        api.assertApiPostSearch(searchByNamePayload("sampleUpdateUser"), FULL_ACCESS_USER, HttpStatus.SC_OK, 1, "sampleUpdateUser");

        // can delete own; cannot delete admin’s under sharing rules
        api.assertApiDelete(userResId, FULL_ACCESS_USER, HttpStatus.SC_OK);
        api.assertApiDelete(adminResId, FULL_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
    }

    private void assertAdminCert_Enabled() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            // read/update
            TestRestClient.HttpResponse resp = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
            resp.assertStatusCode(HttpStatus.SC_OK);

            resp = client.postJson(SAMPLE_RESOURCE_UPDATE_ENDPOINT + "/" + adminResId, "{\"name\":\"sampleUpdated\"}");
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.getBody(), containsString("sampleUpdated"));

            // share/revoke handlers exist → expect 200 for admin path
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

            // search works
            resp = client.get(SAMPLE_RESOURCE_SEARCH_ENDPOINT);
            resp.assertStatusCode(HttpStatus.SC_OK);
            assertThat(resp.getBody(), containsString("sampleUpdated"));

            resp = client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchAllPayload());
            resp.assertStatusCode(HttpStatus.SC_OK);

            resp = client.postJson(SAMPLE_RESOURCE_SEARCH_ENDPOINT, searchByNamePayload("sampleUpdated"));
            resp.assertStatusCode(HttpStatus.SC_OK);

            // delete ok
            resp = client.delete(SAMPLE_RESOURCE_DELETE_ENDPOINT + "/" + adminResId);
            resp.assertStatusCode(HttpStatus.SC_OK);
        }
    }
}
