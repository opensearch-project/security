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
import org.apache.hc.core5.http.message.BasicHeader;
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
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access when shared with full-access (sampleAllAG action-group).
 * All tests are against USER_ADMIN's resource created during setup.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ResourceSharingMultiTenancyTests {

    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String resourceId;

    @Before
    public void setup() {
        resourceId = api.createSampleResourceAs(USER_ADMIN, new BasicHeader("securitytenant", "customtenant"));
        api.awaitSharingEntry(resourceId); // wait until sharing entry is created
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void testCreateResourceWithMultiTenancyEnabled() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            TestRestClient.HttpResponse sharingInfoResponse = client.get(
                "_plugins/_security/api/resource/share?resource_id=" + resourceId + "&resource_type=" + RESOURCE_INDEX_NAME
            );
            assertThat(sharingInfoResponse.getBody(), containsString("\"created_by\":{\"user\":\"admin\",\"tenant\":\"customtenant\"}"));
        }
    }
}
