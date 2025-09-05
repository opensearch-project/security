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
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.sample.resource.TestUtils.NO_ACCESS_USER;
import static org.opensearch.sample.resource.TestUtils.RESOURCE_SHARING_INDEX;
import static org.opensearch.sample.resource.TestUtils.SECURITY_TYPES_ENDPOINT;
import static org.opensearch.sample.resource.TestUtils.newCluster;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * This test file tests the types API that lists available resource types
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class TypesApiTests {
    @ClassRule
    public static LocalCluster cluster = newCluster(true, true);

    @After
    public void clearIndices() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            client.delete(RESOURCE_INDEX_NAME);
            client.delete(RESOURCE_SHARING_INDEX);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testTypesApi_mustListSampleResourceAsAType() {
        // no-access-user should be able to call types api that lists available resource types
        try (TestRestClient client = cluster.getRestClient(NO_ACCESS_USER)) {
            TestRestClient.HttpResponse response = client.get(SECURITY_TYPES_ENDPOINT);
            response.assertStatusCode(HttpStatus.SC_OK);
            List<Object> types = (List<Object>) response.bodyAsMap().get("types");
            assertThat(types.size(), equalTo(1));
            Map<String, Object> responseBody = (Map<String, Object>) types.getFirst();
            assertThat(responseBody.get("type"), equalTo("org.opensearch.sample.SampleResource"));
            assertThat(responseBody.get("index"), equalTo(".sample_resource"));
            assertThat(responseBody.get("action_groups"), equalTo(List.of("sample_read_only", "sample_read_write", "sample_full_access")));
        }

    }
}
