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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.plugin.transport.grpc.GrpcPlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import io.grpc.StatusRuntimeException;

import static org.opensearch.security.grpc.GrpcClientAuthNoneTests.assertBulkAndSearchTestIndex;
import static org.opensearch.security.grpc.GrpcHelpers.CLIENT_AUTH_OPT;
import static org.opensearch.security.grpc.GrpcHelpers.SECURE_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GrpcClientAuthOptionalTests {
    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .plugin(GrpcPlugin.class)
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SECURE_GRPC_TRANSPORT_SETTINGS)
        .loadConfigurationIntoIndex(false)
        .sslOnly(true)
        .nodeSettings(CLIENT_AUTH_OPT)
        .build();

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
    public void testBulkAndSearchUntrustedSecureChannel() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            assertBulkAndSearchTestIndex(GrpcHelpers.secureUntrustedChannel());
        });
        assertEquals("UNAVAILABLE: ssl exception", exception.getMessage());
    }
}
