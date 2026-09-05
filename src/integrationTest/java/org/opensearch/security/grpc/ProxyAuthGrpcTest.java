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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.XffConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.grpc.GrpcPlugin;

import io.grpc.Channel;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;

import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_ROLE;
import static org.opensearch.security.grpc.GrpcHelpers.GRPC_INDEX_USER;
import static org.opensearch.security.grpc.GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS;
import static org.opensearch.security.grpc.GrpcHelpers.TEST_CERTIFICATES;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.doBulk;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Integration test for proxy_auth_domain over gRPC.
 * Verifies that HTTPProxyAuthenticator is exercised for gRPC requests (i.e. "proxy" is
 * recognized by GRPC_SUPPORTED_AUTH in BackendRegistry) and that the caller identity
 * carried in x-proxy-user / x-proxy-roles is honored when the upstream socket matches
 * the trusted internal-proxies allowlist.
 */
public class ProxyAuthGrpcTest {

    private static final String PROXY_USER_HEADER = "x-proxy-user";
    private static final String PROXY_ROLES_HEADER = "x-proxy-roles";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";

    private static final Map<String, Object> PROXY_AUTHENTICATOR_CONFIG = Map.of(
        "user_header",
        PROXY_USER_HEADER,
        "roles_header",
        PROXY_ROLES_HEADER
    );

    // proxy_auth_domain first, basic as fallback so cluster bootstrap (securityadmin over REST) still works
    public static final TestSecurityConfig.AuthcDomain PROXY_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain("proxy_auth_domain", -5, true)
        .httpAuthenticator(
            new TestSecurityConfig.AuthcDomain.HttpAuthenticator("proxy").challenge(false).config(PROXY_AUTHENTICATOR_CONFIG)
        )
        .backend(new TestSecurityConfig.AuthcDomain.AuthenticationBackend("noop"));

    public static final TestSecurityConfig.AuthcDomain BASIC_FALLBACK = new TestSecurityConfig.AuthcDomain("basic", 0, true)
        .httpAuthenticator("basic")
        .backend("internal");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .certificates(TEST_CERTIFICATES)
        .nodeSettings(SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS)
        .xff(new XffConfig(true).internalProxiesRegexp("127\\.0\\.0\\.1"))
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
        .users(GRPC_INDEX_USER)
        .roles(GRPC_INDEX_ROLE)
        // Map both the internal user (for basic fallback / bootstrap) and the proxy-supplied identity
        // to the role that grants bulk permissions.
        .rolesMapping(
            new TestSecurityConfig.RoleMapping(GRPC_INDEX_ROLE.getName()).users(GRPC_INDEX_USER.getName(), "kratos-grpc-service")
        )
        .authc(PROXY_AUTH_DOMAIN)
        .authc(BASIC_FALLBACK)
        .build();

    @Test
    public void proxyAuthSucceedsWhenTrustedProxyAndUserHeaderPresent() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor auth = createHeaderInterceptor(
                Map.of(
                    X_FORWARDED_FOR,
                    "127.0.0.1",
                    PROXY_USER_HEADER,
                    "kratos-grpc-service",
                    PROXY_ROLES_HEADER,
                    GRPC_INDEX_ROLE.getName()
                )
            );
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, auth);

            var resp = doBulk(channelWithAuth, "test-grpc-proxyauth-ok", 2);
            assertNotNull(resp);
            assertFalse("Bulk request should succeed with valid proxy headers", resp.getErrors());
            assertEquals(2, resp.getItemsCount());
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void proxyAuthFailsWhenNoXForwardedForHeader() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor auth = createHeaderInterceptor(
                Map.of(PROXY_USER_HEADER, "kratos-grpc-service", PROXY_ROLES_HEADER, GRPC_INDEX_ROLE.getName())
            );
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, auth);
            try {
                doBulk(channelWithAuth, "test-grpc-proxyauth-no-xff", 2);
                fail("Expected UNAUTHENTICATED - XFF_DONE would not be set without X-Forwarded-For header");
            } catch (StatusRuntimeException e) {
                assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
            }
        } finally {
            channel.shutdown();
        }
    }

    @Test
    public void proxyAuthFailsWhenNoUserHeader() throws Exception {
        ManagedChannel channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            ClientInterceptor auth = createHeaderInterceptor(Map.of(X_FORWARDED_FOR, "127.0.0.1"));
            Channel channelWithAuth = io.grpc.ClientInterceptors.intercept(channel, auth);
            try {
                doBulk(channelWithAuth, "test-grpc-proxyauth-no-user", 2);
                fail("Expected UNAUTHENTICATED - proxy_auth_domain produces no credentials without user header");
            } catch (StatusRuntimeException e) {
                assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
            }
        } finally {
            channel.shutdown();
        }
    }
}
