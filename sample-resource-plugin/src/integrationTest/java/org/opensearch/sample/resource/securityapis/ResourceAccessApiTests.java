/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.securityapis;

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_WRITE;
import static org.opensearch.sample.resource.TestUtils.SECURITY_ACCESS_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceAccessApiTests {
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
    public void testResourceAccess_invalidResourceType() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.get(
                SECURITY_ACCESS_ENDPOINT + "?resource_type=some-type&resource_id=" + adminResId
            );
            response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            assertThat(
                response.getBody(),
                containsString("Invalid resource type: some-type. Must be one of: [sample-resource, sample-resource-group]")
            );
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testResourceAccess_ownerGetsResolvedCapabilities() {
        TestRestClient.HttpResponse response = api.getResourceAccess(adminResId, USER_ADMIN);
        response.assertStatusCode(HttpStatus.SC_OK);

        Map<String, Object> access = (Map<String, Object>) response.bodyAsMap().get("access");
        List<String> accessLevels = (List<String>) access.get("access_levels");
        List<String> allowedActions = (List<String>) access.get("allowed_actions");

        assertThat(access.get("resource_id"), equalTo(adminResId));
        assertThat(access.get("resource_type"), equalTo(RESOURCE_TYPE));
        assertThat(access.get("is_owner"), equalTo(Boolean.TRUE));
        assertThat(access.get("is_admin"), equalTo(Boolean.FALSE));
        assertThat(access.get("effective_access_level"), equalTo(SAMPLE_FULL_ACCESS));
        assertThat(accessLevels, hasItems(SAMPLE_READ_ONLY, SAMPLE_READ_WRITE, SAMPLE_FULL_ACCESS));
        assertThat(allowedActions, hasItems("sampleresource:get", "sampleresource:*", "cluster:admin/security/resource/share"));
        assertThat(access.get("can_share"), equalTo(Boolean.TRUE));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testResourceAccess_superAdminGetsResolvedCapabilities() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse response = client.get(
                SECURITY_ACCESS_ENDPOINT + "?resource_type=" + RESOURCE_TYPE + "&resource_id=" + adminResId
            );
            response.assertStatusCode(HttpStatus.SC_OK);

            Map<String, Object> access = (Map<String, Object>) response.bodyAsMap().get("access");
            List<String> accessLevels = (List<String>) access.get("access_levels");
            List<String> allowedActions = (List<String>) access.get("allowed_actions");

            assertThat(access.get("is_owner"), equalTo(Boolean.FALSE));
            assertThat(access.get("is_admin"), equalTo(Boolean.TRUE));
            assertThat(access.get("effective_access_level"), equalTo(SAMPLE_FULL_ACCESS));
            assertThat(accessLevels, hasItems(SAMPLE_READ_ONLY, SAMPLE_READ_WRITE, SAMPLE_FULL_ACCESS));
            assertThat(allowedActions, hasItems("sampleresource:get", "sampleresource:*", "cluster:admin/security/resource/share"));
            assertThat(access.get("can_share"), equalTo(Boolean.TRUE));
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testResourceAccess_readOnlyUserGetsReadOnlyCapabilities() {
        okShareReadOnly(NO_ACCESS_USER);

        TestRestClient.HttpResponse response = api.getResourceAccess(adminResId, NO_ACCESS_USER);
        response.assertStatusCode(HttpStatus.SC_OK);

        Map<String, Object> access = (Map<String, Object>) response.bodyAsMap().get("access");
        List<String> accessLevels = (List<String>) access.get("access_levels");
        List<String> allowedActions = (List<String>) access.get("allowed_actions");

        assertThat(access.get("is_owner"), equalTo(Boolean.FALSE));
        assertThat(access.get("is_admin"), equalTo(Boolean.FALSE));
        assertThat(access.get("effective_access_level"), equalTo(SAMPLE_READ_ONLY));
        assertThat(accessLevels, hasItem(SAMPLE_READ_ONLY));
        assertThat(allowedActions, hasItems(SAMPLE_READ_ONLY, "sampleresource:get"));
        assertThat(allowedActions, not(hasItem("sampleresource:update")));
        assertThat(allowedActions, not(hasItem("cluster:admin/security/resource/share")));
        assertThat(access.get("can_share"), equalTo(Boolean.FALSE));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testResourceAccess_readWriteUserGetsEditButNotShare() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.putJson(
                TestUtils.SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(
                    adminResId,
                    RESOURCE_TYPE,
                    SAMPLE_READ_WRITE,
                    org.opensearch.security.resources.sharing.Recipient.USERS,
                    LIMITED_ACCESS_USER.getName()
                )
            );
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        TestRestClient.HttpResponse response = api.getResourceAccess(adminResId, LIMITED_ACCESS_USER);
        response.assertStatusCode(HttpStatus.SC_OK);

        Map<String, Object> access = (Map<String, Object>) response.bodyAsMap().get("access");
        List<String> allowedActions = (List<String>) access.get("allowed_actions");

        assertThat(access.get("effective_access_level"), equalTo(SAMPLE_READ_WRITE));
        assertThat(((List<String>) access.get("access_levels")), hasItem(SAMPLE_READ_WRITE));
        assertThat(allowedActions, hasItems(SAMPLE_READ_WRITE, "sampleresource:*"));
        assertThat(allowedActions, not(hasItem("cluster:admin/security/resource/share")));
        assertThat(access.get("can_share"), equalTo(Boolean.FALSE));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testResourceAccess_fullAccessUserGetsShareCapability() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.putJson(
                TestUtils.SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(
                    adminResId,
                    RESOURCE_TYPE,
                    SAMPLE_FULL_ACCESS,
                    org.opensearch.security.resources.sharing.Recipient.USERS,
                    FULL_ACCESS_USER.getName()
                )
            );
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        TestRestClient.HttpResponse response = api.getResourceAccess(adminResId, FULL_ACCESS_USER);
        response.assertStatusCode(HttpStatus.SC_OK);

        Map<String, Object> access = (Map<String, Object>) response.bodyAsMap().get("access");
        List<String> allowedActions = (List<String>) access.get("allowed_actions");

        assertThat(access.get("effective_access_level"), equalTo(SAMPLE_FULL_ACCESS));
        assertThat(((List<String>) access.get("access_levels")), hasItem(SAMPLE_FULL_ACCESS));
        assertThat(allowedActions, hasItems(SAMPLE_FULL_ACCESS, "sampleresource:*", "cluster:admin/security/resource/share"));
        assertThat(access.get("can_share"), equalTo(Boolean.TRUE));
    }

    @Test
    public void testResourceAccess_returnsForbiddenWhenUserHasNoAccess() {
        TestRestClient.HttpResponse response = api.getResourceAccess(adminResId, NO_ACCESS_USER);
        response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
        assertThat(response.getBody(), containsString("Not authorized to access resource"));
    }

    private void okShareReadOnly(org.opensearch.test.framework.TestSecurityConfig.User user) {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse response = client.putJson(
                TestUtils.SECURITY_SHARE_ENDPOINT,
                TestUtils.putSharingInfoPayload(
                    adminResId,
                    RESOURCE_TYPE,
                    SAMPLE_READ_ONLY,
                    org.opensearch.security.resources.sharing.Recipient.USERS,
                    user.getName()
                )
            );
            response.assertStatusCode(HttpStatus.SC_OK);
        }
    }
}
