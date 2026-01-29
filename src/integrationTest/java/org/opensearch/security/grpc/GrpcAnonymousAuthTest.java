/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.grpc;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import io.grpc.Channel;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.doBulk;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class GrpcAnonymousAuthTest {

    // Role with bulk permissions for anonymous user
    static final TestSecurityConfig.Role ANONYMOUS_BULK_ROLE = new TestSecurityConfig.Role("anonymous_bulk_role").clusterPermissions(
        "indices:data/write/bulk*"
    ).indexPermissions("indices:data/write/bulk*", "indices:admin/mapping/put", "indices:admin/create", "indices:data/write/index").on("*");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS)
        .nodeSettings(Map.of("plugins.security.authcz.admin_dn", Arrays.asList(TEST_CERTIFICATES.getAdminDNs())))
        .plugin(
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
            new PluginInfo(
                OpenSearchSecurityPlugin.class.getName(),
                "classpath plugin",
                "NA",
                Version.CURRENT,
                "21",
                OpenSearchSecurityPlugin.class.getName(),
                null,
                List.of("org.opensearch.transport.grpc.GrpcPlugin"),
                false
            )
        )
        .anonymousAuth(true)
        .roles(ANONYMOUS_BULK_ROLE)
        .rolesMapping(new TestSecurityConfig.RoleMapping(ANONYMOUS_BULK_ROLE.getName()).users("*"))
        .build();

    @Test
    public void testAnonymousAuthRejectedForGrpc() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            try {
                doBulk(channel, "test-anonymous-rejected", 2);
                fail("Expected rejection - anonymous auth not supported for gRPC");
            } catch (StatusRuntimeException e) {
                assertEquals(Status.Code.INVALID_ARGUMENT, e.getStatus().getCode());
                assertEquals("Anonymous auth not supported over gRPC", e.getStatus().getDescription());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void testInvalidAuthHeaderRejected() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor mockAuthInterceptor = createHeaderInterceptor(Map.of("Authorization", "mock-auth-header"));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, mockAuthInterceptor);

            try {
                doBulk(channelWithAuth, "test-invalid-auth", 2);
                fail("Expected authentication failure - invalid auth header");
            } catch (StatusRuntimeException e) {
                assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
            }
        } finally {
            channel.shutdown();
        }
    }
}
