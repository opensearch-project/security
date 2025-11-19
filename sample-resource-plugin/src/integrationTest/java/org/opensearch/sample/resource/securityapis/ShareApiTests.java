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
import java.util.Map;
import java.util.Set;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.security.resources.sharing.Recipient;
import org.opensearch.security.resources.sharing.Recipients;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_READ_ONLY;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.putSharingInfoPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * This test file tests the share API defined by the security plugin.
 * Resource access control feature and system index protection are assumed to be enabled
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ ShareApiTests.RoutesTests.class })
public class ShareApiTests {
    /**
     * Base test class providing shared cluster setup and teardown
     */
    public static abstract class BaseTests {
        @ClassRule
        public static LocalCluster cluster = newCluster(true, true);

        @After
        public void clearIndices() {
            try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
                client.delete(RESOURCE_INDEX_NAME);
                client.delete(RESOURCE_SHARING_INDEX);
            }
        }
    }

    /**
     * Tests exercising the share API endpoints, GET, PUT & PATCH
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class RoutesTests extends BaseTests {
        private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
        private String adminResId;

        @Before
        public void setup() {
            adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(adminResId);
        }

        @Test
        public void testGibberishPayload() {
            // test get with gibberish payload
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.get(
                    SECURITY_SHARE_ENDPOINT + "?resource_id=" + "some-id" + "&resource_type=" + RESOURCE_TYPE
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN); // since resource-index exists but resource-id doesn't, but user
                                                                    // shouldn't know that

                response = client.get(SECURITY_SHARE_ENDPOINT + "?resource_id=" + adminResId + "&resource_type=" + "some-type");
                response.assertStatusCode(HttpStatus.SC_BAD_REQUEST); // since type doesn't exist, so does the corresponding index
            }

            // test put with gibberish value
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload("some-id", RESOURCE_TYPE, SAMPLE_READ_ONLY, Recipient.USERS, NO_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN); // since resource-index exists but resource-id doesn't, but user
                                                                    // shouldn't know that

                response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, "some_type", SAMPLE_READ_ONLY, Recipient.USERS, NO_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_BAD_REQUEST); // since type doesn't exist, so does the corresponding index
            }

            // test patch with gibberish
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                Map<Recipient, Set<String>> recs = new HashMap<>();
                Set<String> users = new HashSet<>();
                users.add(FULL_ACCESS_USER.getName());
                recs.put(Recipient.USERS, users);
                Recipients recipients = new Recipients(recs);

                TestUtils.PatchSharingInfoPayloadBuilder patchSharingInfoPayloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
                patchSharingInfoPayloadBuilder.resourceId("some-id").resourceType(RESOURCE_TYPE).share(recipients, SAMPLE_FULL_ACCESS);
                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);

                patchSharingInfoPayloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
                patchSharingInfoPayloadBuilder.resourceId(adminResId).resourceType("some-type").share(recipients, SAMPLE_FULL_ACCESS);
                response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_BAD_REQUEST);
            }

        }

        @Test
        public void testPutSharingInfo() {
            // non-permission user cannot share resource
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_READ_ONLY, Recipient.USERS, NO_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // a sharing entry should be created successfully since admin has access to share API
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, LIMITED_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.getBody(), containsString(LIMITED_ACCESS_USER.getName()));
                assertThat(response.getBody(), not(containsString(NO_ACCESS_USER.getName())));
            }

            // non-permission user will now have access to directly call share API
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_READ_ONLY, Recipient.USERS, NO_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.getBody(), containsString(NO_ACCESS_USER.getName()));
            }
        }

        @Test
        public void testGetSharingInfo() {
            // non-permission user cannot list shared resources,
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.get(
                    SECURITY_SHARE_ENDPOINT + "?resource_id=" + adminResId + "&resource_type=" + RESOURCE_TYPE
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // a sharing entry should be created successfully since admin has access to share API
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS, Recipient.USERS, FULL_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.getBody(), containsString(FULL_ACCESS_USER.getName()));
            }

            // non-permission user can now list shared_with resources by calling share API
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.get(
                    SECURITY_SHARE_ENDPOINT + "?resource_id=" + adminResId + "&resource_type=" + RESOURCE_TYPE
                );
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.bodyAsJsonNode().get("sharing_info").get("resource_id").asText(), equalTo(adminResId));
            }
        }

        @Test
        public void testPatchSharingInfo() {
            Map<Recipient, Set<String>> recs = new HashMap<>();
            Set<String> users = new HashSet<>();
            users.add(FULL_ACCESS_USER.getName());
            recs.put(Recipient.USERS, users);
            Recipients recipients = new Recipients(recs);

            TestUtils.PatchSharingInfoPayloadBuilder patchSharingInfoPayloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
            patchSharingInfoPayloadBuilder.resourceId(adminResId).resourceType(RESOURCE_TYPE).share(recipients, SAMPLE_FULL_ACCESS);

            // full-access user cannot share with itself since user doesn't have permission to share
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // a sharing entry should be created successfully since admin has access to share API
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.getBody(), containsString(FULL_ACCESS_USER.getName()));
            }

            // limited access user will not be able to call patch endpoint
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // full-access user will now be able to patch and grant access to limited access user
            // they can also shoot themselves in the foot and remove own access
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                // add limited user
                users.add(LIMITED_ACCESS_USER.getName());
                patchSharingInfoPayloadBuilder.share(recipients, SAMPLE_FULL_ACCESS);
                // remove self
                Set<String> revokedUsers = new HashSet<>();
                revokedUsers.add(FULL_ACCESS_USER.getName());
                recs.put(Recipient.USERS, revokedUsers);
                recipients = new Recipients(recs);
                patchSharingInfoPayloadBuilder.revoke(recipients, SAMPLE_FULL_ACCESS);

                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_OK);
            }

            // limited access user will now be able to call get and patch endpoint, but full-access won't
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                response.assertStatusCode(HttpStatus.SC_OK);
                response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_OK);
            }
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
                response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
        }

        @Test
        public void testPostSharingInfo() {
            Map<Recipient, Set<String>> recs = new HashMap<>();
            Set<String> users = new HashSet<>();
            users.add(FULL_ACCESS_USER.getName());
            recs.put(Recipient.USERS, users);
            Recipients recipients = new Recipients(recs);

            TestUtils.PatchSharingInfoPayloadBuilder patchSharingInfoPayloadBuilder = new TestUtils.PatchSharingInfoPayloadBuilder();
            patchSharingInfoPayloadBuilder.resourceId(adminResId).resourceType(RESOURCE_TYPE).share(recipients, SAMPLE_FULL_ACCESS);

            // full-access user cannot share with itself since user doesn't have permission to share
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.post(
                    SECURITY_SHARE_ENDPOINT,
                    new StringEntity(patchSharingInfoPayloadBuilder.build(), ContentType.APPLICATION_JSON)
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // a sharing entry should be created successfully since admin has access to share API
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.post(
                    SECURITY_SHARE_ENDPOINT,
                    new StringEntity(patchSharingInfoPayloadBuilder.build(), ContentType.APPLICATION_JSON)
                );
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.getBody(), containsString(FULL_ACCESS_USER.getName()));
            }

            // limited access user will not be able to call patch endpoint
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.post(
                    SECURITY_SHARE_ENDPOINT,
                    new StringEntity(patchSharingInfoPayloadBuilder.build(), ContentType.APPLICATION_JSON)
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // full-access user will now be able to patch and grant access to limited access user
            // they can also shoot themselves in the foot and remove own access
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                // add limited user
                users.add(LIMITED_ACCESS_USER.getName());
                patchSharingInfoPayloadBuilder.share(recipients, SAMPLE_FULL_ACCESS);
                // remove self
                Set<String> revokedUsers = new HashSet<>();
                revokedUsers.add(FULL_ACCESS_USER.getName());
                recs.put(Recipient.USERS, revokedUsers);
                recipients = new Recipients(recs);
                patchSharingInfoPayloadBuilder.revoke(recipients, SAMPLE_FULL_ACCESS);

                TestRestClient.HttpResponse response = client.post(
                    SECURITY_SHARE_ENDPOINT,
                    new StringEntity(patchSharingInfoPayloadBuilder.build(), ContentType.APPLICATION_JSON)
                );
                response.assertStatusCode(HttpStatus.SC_OK);
            }

            // limited access user will now be able to call get and patch endpoint, but full-access won't
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                response.assertStatusCode(HttpStatus.SC_OK);
                response = client.post(
                    SECURITY_SHARE_ENDPOINT,
                    new StringEntity(patchSharingInfoPayloadBuilder.build(), ContentType.APPLICATION_JSON)
                );
                response.assertStatusCode(HttpStatus.SC_OK);
            }
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.get(SAMPLE_RESOURCE_GET_ENDPOINT + "/" + adminResId);
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
                response = client.post(
                    SECURITY_SHARE_ENDPOINT,
                    new StringEntity(patchSharingInfoPayloadBuilder.build(), ContentType.APPLICATION_JSON)
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
        }
    }

}
