/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.opensearch.sample.resource.TestHelper.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestHelper.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestHelper.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestHelper.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestHelper.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestHelper.putSharingInfoPayload;
import static org.opensearch.sample.resource.TestHelper.sampleAllAG;
import static org.opensearch.sample.resource.TestHelper.sampleReadOnlyAG;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
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
            .users(USER_ADMIN, FULL_ACCESS_USER, LIMITED_ACCESS_USER, NO_ACCESS_USER)
            .actionGroups(sampleReadOnlyAG, sampleAllAG)
            .nodeSettings(Map.of(OPENSEARCH_RESOURCE_SHARING_ENABLED, true, SECURITY_SYSTEM_INDICES_ENABLED_KEY, true))
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
     * Tests exercising the share API endpoints, GET, PUT & PATCH
     */
    @RunWith(RandomizedRunner.class)
    @ThreadLeakScope(ThreadLeakScope.Scope.NONE)
    public static class RoutesTests extends BaseTests {
        private final TestHelper.ApiHelper api = new TestHelper.ApiHelper(cluster);
        private String adminResId;

        @Before
        public void setup() {
            adminResId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry();
        }

        @Test
        public void testPutSharingInfo() {
            // non-permission user cannot share resource
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_INDEX_NAME, sampleReadOnlyAG.name(), NO_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // a sharing entry should be created successfully since admin has access to share API
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_INDEX_NAME, sampleAllAG.name(), LIMITED_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.getBody(), containsString(LIMITED_ACCESS_USER.getName()));
                assertThat(response.getBody(), not(containsString(NO_ACCESS_USER.getName())));
            }

            // non-permission user will now have access to directly call share API
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_INDEX_NAME, sampleReadOnlyAG.name(), NO_ACCESS_USER.getName())
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
                    SECURITY_SHARE_ENDPOINT + "?resource_id=" + adminResId + "&resource_index=" + RESOURCE_INDEX_NAME
                );
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }

            // a sharing entry should be created successfully since admin has access to share API
            try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
                TestRestClient.HttpResponse response = client.putJson(
                    SECURITY_SHARE_ENDPOINT,
                    putSharingInfoPayload(adminResId, RESOURCE_INDEX_NAME, sampleAllAG.name(), FULL_ACCESS_USER.getName())
                );
                response.assertStatusCode(HttpStatus.SC_OK);
                assertThat(response.getBody(), containsString(FULL_ACCESS_USER.getName()));
            }

            // non-permission user can now list shared_with resources by calling share API
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.get(
                    SECURITY_SHARE_ENDPOINT + "?resource_id=" + adminResId + "&resource_index=" + RESOURCE_INDEX_NAME
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

            TestHelper.PatchSharingInfoPayloadBuilder patchSharingInfoPayloadBuilder = new TestHelper.PatchSharingInfoPayloadBuilder();
            patchSharingInfoPayloadBuilder.resourceId(adminResId).resourceIndex(RESOURCE_INDEX_NAME).share(recipients, sampleAllAG.name());

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
                patchSharingInfoPayloadBuilder.share(recipients, sampleAllAG.name());
                // remove self
                Set<String> revokedUsers = new HashSet<>();
                revokedUsers.add(FULL_ACCESS_USER.getName());
                recs.put(Recipient.USERS, revokedUsers);
                recipients = new Recipients(recs);
                patchSharingInfoPayloadBuilder.revoke(recipients, sampleAllAG.name());

                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_OK);
            }

            // limited access user will now be able to call patch endpoint, but full-access won't
            try (TestRestClient client = cluster.getRestClient(LIMITED_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_OK);
            }
            try (TestRestClient client = cluster.getRestClient(FULL_ACCESS_USER)) {
                TestRestClient.HttpResponse response = client.patch(SECURITY_SHARE_ENDPOINT, patchSharingInfoPayloadBuilder.build());
                response.assertStatusCode(HttpStatus.SC_FORBIDDEN);
            }
        }
    }

}
