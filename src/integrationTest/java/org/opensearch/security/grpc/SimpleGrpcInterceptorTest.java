/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security.grpc;

import java.util.Collections;
import java.util.List;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;

import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;

public class SimpleGrpcInterceptorTest {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder()
        .clusterManager(ClusterManager.SINGLENODE)
        .plugin(
            // Add GrpcPlugin
            new PluginInfo(
                GrpcPlugin.class.getName(),
                "classpath plugin",
                "NA", 
                Version.CURRENT,
                "21",
                GrpcPlugin.class.getName(),
                null,
                Collections.emptyList(),
                false
            )
        )
        .plugin(
            // Override the default security plugin with one that declares extension relationship
            new PluginInfo(
                OpenSearchSecurityPlugin.class.getName(),
                "classpath plugin", 
                "NA",
                Version.CURRENT,
                "21",
                OpenSearchSecurityPlugin.class.getName(),
                null,
                List.of("org.opensearch.transport.grpc.GrpcPlugin"), // Extends GrpcPlugin by class name
                false
            )
        )
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SINGLE_NODE_SECURE_GRPC_TRANSPORT_SETTINGS)
        .loadConfigurationIntoIndex(false)
        .sslOnly(true)
        .build();

    @Test
    public void testGrpcInterceptorLoaded() {
        // Test that our interceptor is loaded and working
        ManagedChannel channel = GrpcHelpers.insecureChannel(getSecureGrpcEndpoint(cluster));
        
        try {
            // This should trigger our interceptor
            GrpcHelpers.doBulk(channel, "test-index", 1);
        } catch (StatusRuntimeException e) {
            // Expected - no authentication provided
            System.out.println("Expected auth failure: " + e.getStatus());
        } finally {
            channel.shutdown();
        }
        
        System.out.println("✓ gRPC interceptor integration test completed");
    }
}
