/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.grpc;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.grpc.GrpcHelpers.CLIENT_AUTH_OPT;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.baseGrpcCluster;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GrpcTestsClientAuthOptionalTest {
    @ClassRule
    public static LocalCluster cluster = baseGrpcCluster()
            .nodeSettings(CLIENT_AUTH_OPT)
            .build();

    @Test
    public void testSearch() {
        long testDocs = 9;
        String testIndex = "test-index";
        GrpcHelpers.createTestIndex(cluster.getRestClient(), testIndex, testDocs);
        SearchResponse resp = GrpcHelpers.grpcMatchAllQuery(cluster.getGrpcClient(TEST_CERTIFICATES), testIndex, 100);
        assertThat("Search response should not be null", resp != null);
        SearchResponse.ResponseCase respCase = resp.getResponseCase();
        assertThat("Search response should indicate success", respCase.getNumber() == SearchResponse.ResponseCase.RESPONSE_BODY.getNumber());
        long hits = resp.getResponseBody().getHits().getTotal().getTotalHits().getValue();
        assertThat("Search response has correct hits count", hits == 9);
    }
}
