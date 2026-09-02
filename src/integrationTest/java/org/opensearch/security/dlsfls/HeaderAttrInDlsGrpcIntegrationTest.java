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

package org.opensearch.security.dlsfls;

import java.util.Map;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.grpc.GrpcHelpers;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.dlsfls.HeaderAttrInDlsIntegrationTest.DLS_INDEX;
import static org.opensearch.security.dlsfls.HeaderAttrInDlsIntegrationTest.SINGLE_VALUE_DLS_USER;
import static org.opensearch.security.grpc.GrpcHelpers.SECURITY_WITH_GRPC_PLUGIN;
import static org.opensearch.security.grpc.GrpcHelpers.createChannelWithBasicAuthorization;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;

/**
 * due to a bug the gRPC tests are currently flaky when run with a multi-node cluster. thus we temporarily have to use a single-node cluster for this test.
 * as we have to avoid having other nodes running in the same JVM we have to split this into a separate test class from the HTTP tests in {@link HeaderAttrInDlsIntegrationTest}.
 * TODO: remove & use a single cluster for HTTP + gRPC tests once this ticket is fixed: https://github.com/opensearch-project/security/issues/6431
 */
public class HeaderAttrInDlsGrpcIntegrationTest {
    @ClassRule
    public static final LocalCluster cluster = HeaderAttrInDlsIntegrationTest.clusterBuilder.clusterManager(ClusterManager.SINGLENODE)
        .nodeSettings(GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS)
        .nodeSettings(GrpcHelpers.CLIENT_AUTH_REQUIRE)
        .plugin(SECURITY_WITH_GRPC_PLUGIN)
        .build();

    @BeforeClass
    public static void createTestData() {
        HeaderAttrInDlsIntegrationTest.createTestData(cluster);
    }

    @Test
    public void testGrpcChannel() throws Exception {
        final var channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            final var channelWithAuth = createChannelWithBasicAuthorization(
                channel,
                SINGLE_VALUE_DLS_USER.getName(),
                SINGLE_VALUE_DLS_USER.getPassword()
            );
            final var authInterceptor = createHeaderInterceptor(Map.of("X-Example-Header", "foobar"));
            final var channelWithHeader = io.grpc.ClientInterceptors.intercept(channelWithAuth, authInterceptor);

            final var searchResp = GrpcHelpers.doMatchAll(channelWithHeader, DLS_INDEX, 10);
            assertThat(searchResp, notNullValue());
            assertThat(searchResp.getHits().getTotal().getTotalHits().getValue(), is(1L));
        } finally {
            channel.shutdown();
        }
    }
}
