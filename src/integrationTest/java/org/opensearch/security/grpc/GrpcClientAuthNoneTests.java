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
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.protobufs.BulkResponse;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.test.framework.cluster.LocalCluster;

import java.io.IOException;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.opensearch.security.grpc.GrpcHelpers.CLIENT_AUTH_NONE;
import static org.opensearch.security.grpc.GrpcHelpers.baseGrpcCluster;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GrpcClientAuthNoneTests {
    @ClassRule
    public static LocalCluster cluster = baseGrpcCluster()
            .nodeSettings(CLIENT_AUTH_NONE)
            .build();

    public static void assertBulkAndSearchTestIndex(ManagedChannel channel) {
        int testDocs = (int)(Math.random() * 101);
        String testIndex = UUID.randomUUID().toString().substring(0, 10);

        BulkResponse bulkResp = GrpcHelpers.doBulk(channel, testIndex, testDocs);
        assertThat("Bulk response should not be null", bulkResp != null);
        assertThat("Bulk response should not contain errors", !bulkResp.hasBulkErrorResponse());
        assertThat("Bulk response should have response for all docs indexed", bulkResp.getBulkResponseBody().getItemsCount() == testDocs);

        SearchResponse searchResp = GrpcHelpers.doMatchAll(channel, testIndex, 10);
        assertThat("Search response should not be null", searchResp != null);
        assertThat("Search response should indicate success", searchResp.getResponseCase().getNumber() == SearchResponse.ResponseCase.RESPONSE_BODY.getNumber());
        assertThat("Search response has correct hits count", searchResp.getResponseBody().getHits().getTotal().getTotalHits().getValue() == testDocs);
    }

    @Test
    public void testPlaintextChannel() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            assertBulkAndSearchTestIndex(GrpcHelpers.plaintextChannel());
        });
        assertEquals("UNAVAILABLE: Network closed for unknown reason", exception.getMessage());
    }

    @Test
    public void testBulkAndSearchInsecureChannel() {
        assertBulkAndSearchTestIndex(GrpcHelpers.insecureChannel());
    }

    @Test
    public void testBulkAndSearchSecureChannel() throws IOException {
        assertBulkAndSearchTestIndex(GrpcHelpers.secureChannel());
    }

    @Test
    public void testBulkAndSearchUntrustedSecureChannel() throws IOException {
        assertBulkAndSearchTestIndex(GrpcHelpers.secureUntrustedChannel());
    }
}
