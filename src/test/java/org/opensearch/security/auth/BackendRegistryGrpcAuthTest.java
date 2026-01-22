/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.filter.GrpcRequestChannel;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.threadpool.ThreadPool;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class BackendRegistryGrpcAuthTest {

    @Mock
    private ThreadPool threadPool;

    @Mock
    private AuditLog auditLog;

    @Mock
    private XFFResolver xffResolver;

    @Mock
    private AdminDNs adminDns;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    private BackendRegistry backendRegistry;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        Settings settings = Settings.builder().put("plugins.security.unsupported.inject_user.enabled", true).build();

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);

        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);

        when(clusterInfoHolder.hasClusterManager()).thenReturn(true);
        when(xffResolver.resolve(any())).thenReturn(
            new org.opensearch.core.common.transport.TransportAddress(new InetSocketAddress("127.0.0.1", 9200))
        );

        // no admin user configured - ensure these checks are false
        when(adminDns.isAdmin(any())).thenReturn(false);
        when(adminDns.isAdminDN(any())).thenReturn(false);
    }

    @Test
    public void testGrpcAuthenticateWithNoCredentials() {
        GrpcRequestChannel request = createTestRequest(new HashMap<>());

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail without credentials", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateRejectsTenantHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("securitytenant", "test-tenant");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail with tenant header", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 400 Bad Request", 400, request.getQueuedResponse().get().getStatus());
        assertTrue(
            "Error message should mention tenant",
            request.getQueuedResponse().get().getBody().contains("Tenant selection not supported")
        );
    }

    @Test
    public void testGrpcAuthenticateRejectsImpersonationHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("opendistro_security_impersonate_as", "someuser");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail with impersonation header", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 403 Forbidden", 403, request.getQueuedResponse().get().getStatus());
        assertTrue(
            "Error message should mention impersonation",
            request.getQueuedResponse().get().getBody().contains("User impersonation not supported")
        );
    }

    @Test
    public void testGrpcAuthenticateWithInvalidJWT() {
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer invalid.jwt.token");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail with invalid JWT", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithMalformedJWT() {
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer malformed-token");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail with malformed JWT", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithEmptyAuthorizationHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail with empty authorization header", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithBasicAuthHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Basic dXNlcjpwYXNz");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail with non-Bearer token", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateRejectsMultipleUnsupportedFeatures() {
        Map<String, String> headers = new HashMap<>();
        headers.put("securitytenant", "test-tenant");
        headers.put("opendistro_security_impersonate_as", "admin");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should fail with multiple unsupported features", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        // Should fail on first unsupported feature (tenant)
        assertEquals("Should return 400 Bad Request", 400, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithCaseInsensitiveHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("AUTHORIZATION", "Bearer test.jwt.token");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        assertFalse("Authentication should handle case-insensitive headers", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
    }

    @Test
    public void testGrpcAuthenticateWithValidJWTFormatNoAuthDomainConfigured() {
        final byte[] secretKeyBytes = new byte[64];
        final SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
        String validJwt = Jwts.builder()
            .subject("testuser")
            .claim("roles", "admin,user")
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Bearer " + validJwt);

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.gRPCauthenticate(request);

        /*
        Since the BackendRegistry doesn't have JWT configured in these tests, it will reject the request.
        We would like to test a valid JWT but mocking the DynamicConfigModel is complex and more easily covered in
        integration tests. Here we just confirm a valid JWT produces 401 with no auth domains configured.
         */
        assertFalse("Authentication should fail without JWT configuration", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    private GrpcRequestChannel createTestRequest(Map<String, String> headerMap) {
        Metadata metadata = new Metadata();
        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            Metadata.Key<String> key = Metadata.Key.of(entry.getKey(), Metadata.ASCII_STRING_MARSHALLER);
            metadata.put(key, entry.getValue());
        }
        ServerCall<?, ?> serverCall = mock(ServerCall.class);
        return new GrpcRequestChannel(serverCall, metadata);
    }
}
