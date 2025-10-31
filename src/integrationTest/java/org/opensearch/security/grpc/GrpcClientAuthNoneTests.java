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

import java.io.IOException;
import java.util.UUID;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.protobufs.BulkResponse;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;

import static org.opensearch.security.grpc.GrpcHelpers.CLIENT_AUTH_NONE;
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GrpcClientAuthNoneTests {
    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(GrpcPlugin.class)
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SINGLE_NODE_SECURE_GRPC_TRANSPORT_SETTINGS)
        .loadConfigurationIntoIndex(false)
        .sslOnly(true)
        .nodeSettings(CLIENT_AUTH_NONE)
        .build();

    /**
     * Closes the provided managed channel.
     */
    public static void assertBulkAndSearchTestIndex(ManagedChannel channel) {
        int testDocs = (int) (Math.random() * 101);
        String testIndex = UUID.randomUUID().toString().substring(0, 10);

        BulkResponse bulkResp = GrpcHelpers.doBulk(channel, testIndex, testDocs);
        assertNotNull(bulkResp);
        assertFalse(bulkResp.getErrors());
        assertEquals(testDocs, bulkResp.getItemsCount());

        SearchResponse searchResp = GrpcHelpers.doMatchAll(channel, testIndex, 10);
        assertNotNull(searchResp);
        assertEquals(testDocs, searchResp.getHits().getTotal().getTotalHits().getValue());

        channel.shutdown();
    }

    @Test
    public void testPlaintextChannel() {
        ManagedChannel channel = GrpcHelpers.plaintextChannel(getSecureGrpcEndpoint(cluster));
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> { assertBulkAndSearchTestIndex(channel); });
        assertEquals("UNAVAILABLE: Network closed for unknown reason", exception.getMessage());
        channel.shutdown();
    }

    @Test
    public void testBulkAndSearchInsecureChannel() {
        assertBulkAndSearchTestIndex(GrpcHelpers.insecureChannel(getSecureGrpcEndpoint(cluster)));
    }

    @Test
    public void testBulkAndSearchSecureChannel() throws IOException {
        assertBulkAndSearchTestIndex(GrpcHelpers.secureChannel(getSecureGrpcEndpoint(cluster)));
    }

    @Test
    public void testBulkAndSearchUntrustedSecureChannel() throws IOException {
        assertBulkAndSearchTestIndex(GrpcHelpers.secureUntrustedChannel(getSecureGrpcEndpoint(cluster)));
    }
}
