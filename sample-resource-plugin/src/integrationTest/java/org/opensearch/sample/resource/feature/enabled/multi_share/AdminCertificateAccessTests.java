/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled.multi_share;

import java.util.Map;
import java.util.Set;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.PatchSharingInfoPayloadBuilder;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_FULL_ACCESS_RESOURCE_AG;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_DELETE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_GET_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SAMPLE_RESOURCE_UPDATE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.SECURITY_SHARE_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.resource.TestUtils.putSharingInfoPayload;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access on multiple sharing levels.
 * Admin certificate will have access regardless of sharing.
 * All tests are against USER_ADMIN's resource created during setup.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class AdminCertificateAccessTests {
    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    @Test
    public void adminCertificate_canCRUD() {
        TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId); // wait until sharing entry is created
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
            HttpResponse response = client.putJson(
                SECURITY_SHARE_ENDPOINT,
                putSharingInfoPayload(resourceId, RESOURCE_TYPE, SAMPLE_FULL_ACCESS_RESOURCE_AG, Recipient.USERS, NO_ACCESS_USER.getName())
            );

            response.assertStatusCode(HttpStatus.SC_OK);

            PatchSharingInfoPayloadBuilder patchBuilder = new PatchSharingInfoPayloadBuilder();
            patchBuilder.resourceType(RESOURCE_TYPE);
            patchBuilder.resourceId(resourceId);
            patchBuilder.revoke(new Recipients(Map.of(Recipient.USERS, Set.of(NO_ACCESS_USER.getName()))), SAMPLE_FULL_ACCESS_RESOURCE_AG);
            response = client.patch(SECURITY_SHARE_ENDPOINT, patchBuilder.build());

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
