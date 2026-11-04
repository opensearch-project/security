/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.sample.resource.TestUtils;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.api.AbstractApiIntegrationTest.forbidden;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * The sharing index of a resource index is created by its first sharing record, not when the node starts, so a
 * snapshot restore can bring it back without conflicting with an empty copy.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SharingIndexCreationTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(RESOURCE_SHARING_INDEX);
        }
    }

    @Test
    public void theFirstResourceCreatesTheSharingIndex() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.get(RESOURCE_SHARING_INDEX).assertStatusCode(HttpStatus.SC_NOT_FOUND);

            String resourceId = api.createSampleResourceAs(USER_ADMIN);
            api.awaitSharingEntry(resourceId);

            HttpResponse settings = client.get(RESOURCE_SHARING_INDEX + "/_settings?flat_settings=true");
            settings.assertStatusCode(HttpStatus.SC_OK);
            assertThat(settings.getTextFromJsonBody("/" + RESOURCE_SHARING_INDEX + "/settings/index.hidden"), equalTo("true"));
            assertThat(settings.getTextFromJsonBody("/" + RESOURCE_SHARING_INDEX + "/settings/index.number_of_shards"), equalTo("1"));
        }
    }

    @Test
    public void aResourceWithoutASharingIndexIsForbidden() throws Exception {
        String resourceId = api.createSampleResourceAs(USER_ADMIN);
        api.awaitSharingEntry(resourceId);
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_SHARING_INDEX).assertStatusCode(HttpStatus.SC_OK);
        }

        forbidden(() -> api.getResource(resourceId, FULL_ACCESS_USER));
    }
}
