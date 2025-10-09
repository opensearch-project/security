/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.securityapis;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS_RESOURCE_AG;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY_RESOURCE_AG;
import static org.opensearch.sample.resource.TestUtils.SECURITY_LIST_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.putSharingInfoPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This test file tests the list API that lists current user's accessible resources
 * Sharing behaviour is tested in ShareApiTests, this class simply tests that the shared resources are visible after sharing through list api
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AccessibleResourcesApiTests {
    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String adminResId;

    @Before
    public void setup() {
        adminResId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(adminResId);
    }

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(RESOURCE_SHARING_INDEX);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testListAccessibleResources_gibberishParams() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.get(SECURITY_LIST_ENDPOINT + "?resource_type=" + "some-type");
            response.assertStatusCode(HttpStatus.SC_OK);
            List<Object> types = (List<Object>) response.bodyAsMap().get("resources");
            assertThat(types.size(), equalTo(0));
        }
    }

    @SuppressWarnings("unchecked")
    private void assertListApiWithUser(TestSecurityConfig.User user) {
        // Sharing behaviour is tested in ShareApiTests, this class simply tests that the shared resources are visible after sharing through
        // list api
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(SECURITY_LIST_ENDPOINT + "?resource_type=" + RESOURCE_TYPE);
            response.assertStatusCode(HttpStatus.SC_OK);
            List<Object> types = (List<Object>) response.bodyAsMap().get("resources");
            assertThat(types.size(), equalTo(0));
        }
        // share at read-only, can_share should say false
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.putJson(
                SECURITY_SHARE_ENDPOINT,
                putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_READ_ONLY_RESOURCE_AG, Recipient.USERS, user.getName())
            );
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString(user.getName()));
        }
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(SECURITY_LIST_ENDPOINT + "?resource_type=" + RESOURCE_TYPE);
            response.assertStatusCode(HttpStatus.SC_OK);
            List<Object> resources = (List<Object>) response.bodyAsMap().get("resources");
            assertThat(resources.size(), equalTo(1));
            Map<String, Object> resource = (Map<String, Object>) resources.getFirst();
            assertThat(resource.get("resource_id"), equalTo(adminResId));
            assertThat(resource.get("created_by"), equalTo(Map.of("user", USER_ADMIN.getName())));
            assertThat(
                resource.get("share_with"),
                equalTo(Map.of(SAMPLE_READ_ONLY_RESOURCE_AG, Map.of(Recipient.USERS.getName(), List.of(user.getName()))))
            );
            assertThat(resource.get("can_share"), equalTo(Boolean.FALSE));
        }

        // share at full-access, can_share should say true
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Map<Recipient, Set<String>> recs = new HashMap<>();
            Set<String> users = new HashSet<>();
            users.add(user.getName());
            recs.put(Recipient.USERS, users);
            Recipients recipients = new Recipients(recs);

            TestUtils.PatchSharingInfoPayloadBuilder patchSharingInfoPayloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
            patchSharingInfoPayloadBuilder.resourceId(adminResId)
                .resourceType(RESOURCE_TYPE)
                .share(recipients, SAMPLE_FULL_ACCESS_RESOURCE_AG);

            TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString(user.getName()));
        }
        try (TestRestClient client = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse response = client.get(SECURITY_LIST_ENDPOINT + "?resource_type=" + RESOURCE_TYPE);
            response.assertStatusCode(HttpStatus.SC_OK);
            List<Object> resources = (List<Object>) response.bodyAsMap().get("resources");
            assertThat(resources.size(), equalTo(1));
            Map<String, Object> resource = (Map<String, Object>) resources.getFirst();
            assertThat(resource.get("resource_id"), equalTo(adminResId));
            assertThat(resource.get("created_by"), equalTo(Map.of("user", USER_ADMIN.getName())));
            Map<String, Object> shareWith = Map.of(
                SAMPLE_READ_ONLY_RESOURCE_AG,
                Map.of(Recipient.USERS.getName(), List.of(user.getName())),
                SAMPLE_FULL_ACCESS_RESOURCE_AG,
                Map.of(Recipient.USERS.getName(), List.of(user.getName()))
            );
            assertThat(resource.get("share_with"), equalTo(shareWith));
            assertThat(resource.get("can_share"), equalTo(Boolean.TRUE));
        }
    }

    @Test
    public void testListAccessibleResources_noAccessUser() {
        // no-access-user should be able to see resource once shared.
        assertListApiWithUser(NO_ACCESS_USER);
    }

    @Test
    public void testListAccessibleResources_limitedAccessUser() {
        // no-access-user should be able to see resource once shared.
        assertListApiWithUser(LIMITED_ACCESS_USER);
    }

    @Test
    public void testListAccessibleResources_fullAccessUser() {
        // no-access-user should be able to see resource once shared.
        assertListApiWithUser(FULL_ACCESS_USER);
    }

    @SuppressWarnings("unchecked")
    private void assertListApiWithOwnerAndSuperAdmin(TestRestClient client) {
        TestRestClient.HttpResponse response = client.get(SECURITY_LIST_ENDPOINT + "?resource_type=" + RESOURCE_TYPE);
        response.assertStatusCode(HttpStatus.SC_OK);
        List<Object> resources = (List<Object>) response.bodyAsMap().get("resources");
        assertThat(resources.size(), equalTo(1));
        Map<String, Object> resource = (Map<String, Object>) resources.getFirst();
        assertThat(resource.get("resource_id"), equalTo(adminResId));
        assertThat(resource.get("created_by"), equalTo(Map.of("user", USER_ADMIN.getName())));
        assertThat(resource.get("can_share"), equalTo(Boolean.TRUE));
    }

    @Test
    public void testListAccessibleResources_resourceOwner() {
        // owner should be able to see their own resource through list api
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            assertListApiWithOwnerAndSuperAdmin(client);
        }
    }

    @Test
    public void testListAccessibleResources_superAdmin() {
        // owner should be able to see their own resource through list api
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            assertListApiWithOwnerAndSuperAdmin(client);
        }
    }
}
