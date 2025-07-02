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
import org.opensearch.protobufs.BulkResponse;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.grpc.GrpcHelpers.CLIENT_AUTH_OPT;
import static org.opensearch.security.grpc.GrpcHelpers.baseGrpcCluster;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GrpcTestsClientAuthOptionalTest {
    @ClassRule
    public static LocalCluster cluster = baseGrpcCluster()
            .nodeSettings(CLIENT_AUTH_OPT)
            .build();

    @Test
    public void testBulkAndSearchInsecureChannel() {
        long testDocs = 9;
        String testIndex = "test-index";

        BulkResponse bulkResp = GrpcHelpers.doBulk(GrpcHelpers.insecureChannel(), testIndex, testDocs);
        assertThat("Bulk response should not be null", bulkResp != null);
        assertThat("Bulk response should not contain errors", !bulkResp.hasBulkErrorResponse());
        assertThat("Bulk response should have response for all docs indexed", bulkResp.getBulkResponseBody().getItemsCount() == testDocs);

        SearchResponse searchResp = GrpcHelpers.doMatchAll(GrpcHelpers.insecureChannel(), testIndex, 100);
        assertThat("Search response should not be null", searchResp != null);
        assertThat("Search response should indicate success", searchResp.getResponseCase().getNumber() == SearchResponse.ResponseCase.RESPONSE_BODY.getNumber());
        assertThat("Search response has correct hits count", searchResp.getResponseBody().getHits().getTotal().getTotalHits().getValue() == testDocs);
    }

}
