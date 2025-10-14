/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.resource.feature.enabled;

import java.util.List;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
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
import static org.opensearch.sample.resource.TestUtils.FULL_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.LIMITED_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

/**
 * Test resource access when sample-resource is not marked as protected resource, even-though resource sharing protection is enabled.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ExcludedResourceTypeTests {

    // do not include sample resource as protected resource, should behave as if feature was disable for that resource
    @ClassRule
    public static LocalCluster cluster = newCluster(true, true, List.of());

    private final TestUtils.ApiHelper api = new TestUtils.ApiHelper(cluster);
    private String resourceId;

    @Before
    public void setup() {
        resourceId = api.createSampleResourceAs(USER_ADMIN);
    }

    @After
    public void cleanup() {
        api.wipeOutResourceEntries();
    }

    @Test
    public void testSampleResourceSharingIndexExists() {
        // we create resource-sharing index as we need to add index operation listener and we cannot add that dynamically
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            TestRestClient.HttpResponse response = client.get("_cat/indices?expand_wildcards=all");
            response.assertStatusCode(HttpStatus.SC_OK);
            assertThat(response.getBody(), containsString(RESOURCE_SHARING_INDEX));
        }
    }

    @Test
    public void fullAccessUser_canCRUD() {
        api.assertApiGet(resourceId, FULL_ACCESS_USER, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, FULL_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_OK);
        api.assertApiDelete(resourceId, FULL_ACCESS_USER, HttpStatus.SC_OK);
    }

    @Test
    public void limitedAccessUser_canCRUD() {
        api.assertApiGet(resourceId, LIMITED_ACCESS_USER, HttpStatus.SC_OK, "sample");
        api.assertApiUpdate(resourceId, LIMITED_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(resourceId, LIMITED_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
    }

    @Test
    public void noAccessUser_canCRUD() {
        api.assertApiGet(resourceId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN, "");
        api.assertApiUpdate(resourceId, NO_ACCESS_USER, "sampleUpdateAdmin", HttpStatus.SC_FORBIDDEN);
        api.assertApiDelete(resourceId, NO_ACCESS_USER, HttpStatus.SC_FORBIDDEN);
    }
}
