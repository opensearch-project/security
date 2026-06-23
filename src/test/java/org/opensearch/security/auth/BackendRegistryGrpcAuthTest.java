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

package org.opensearch.security.auth;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import javax.crypto.SecretKey;

import com.google.common.collect.ImmutableMultimap;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.filter.GrpcRequestChannel;
import org.opensearch.security.http.HTTPBasicAuthenticator;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.user.User;
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
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        // no admin user configured - ensure these checks are false
        when(adminDns.isAdmin(any())).thenReturn(false);
        when(adminDns.isAdminDN(any())).thenReturn(false);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(clusterInfoHolder.hasClusterManager()).thenReturn(true);
        when(xffResolver.resolve(any())).thenReturn(new TransportAddress(new InetSocketAddress("127.0.0.1", 9200)));

        // backend registry requires at least one auth path is available to initialize.
        // here we enable user injection to allow us to mock/test other failure cases.
        Settings settings = Settings.builder().put("plugins.security.unsupported.inject_user.enabled", true).build();
        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);
    }

    @Test
    public void testGrpcAuthenticateWithNoCredentials() {
        GrpcRequestChannel request = createTestRequest(new HashMap<>());

        boolean result = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail without credentials - No auth domains", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithEmptyAuthorizationHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail with empty authorization header", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
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

        boolean result = backendRegistry.authenticate(request);

        /*
        Since the BackendRegistry doesn't have JWT configured in these tests, it will reject the request.
        We would like to test a valid JWT but mocking the DynamicConfigModel is complex and more easily covered in
        integration tests. Here we just confirm a valid JWT produces 401 with no auth domains configured.
         */
        assertFalse("Authentication should fail without JWT configuration", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithValidBasicAuthFormatNoAuthDomainConfigured() {
        // Create valid Basic Auth header with username:password encoded in Base64
        String credentials = "admin:admin";
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Basic " + base64Credentials);

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.authenticate(request);

        /*
        Since the BackendRegistry doesn't have Basic Auth configured in these tests, it will reject the request.
        We would like to test valid Basic Auth but mocking the DynamicConfigModel is complex and more easily covered in
        integration tests. Here we just confirm valid Basic Auth produces 401 with no auth domains configured.
        This test verifies that Basic Auth is now in GRPC_SUPPORTED_AUTH and will be processed (not skipped).
         */
        assertFalse("Authentication should fail without Basic Auth configuration", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithInvalidBasicAuthFormat() {
        // Create malformed Basic Auth header (not valid Base64)
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Basic not-valid-base64!");

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail with malformed Basic Auth", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithBasicAuthMissingPassword() {
        // Create Basic Auth header with username only (no colon or password)
        String credentials = "admin";
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Basic " + base64Credentials);

        GrpcRequestChannel request = createTestRequest(headers);

        boolean result = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail with missing password", result);
        assertTrue("Should have queued error response", request.getQueuedResponse().isPresent());
        assertEquals("Should return 401 Unauthorized", 401, request.getQueuedResponse().get().getStatus());
    }

    @Test
    public void testGrpcAuthenticateWithValidBasicAuthAndConfiguredDomain() throws Exception {
        // Configure a Basic Auth domain with a mocked backend that accepts "admin:admin"
        AuthenticationBackend mockBackend = mock(AuthenticationBackend.class);
        when(mockBackend.getType()).thenReturn("internal");
        when(mockBackend.authenticate(any())).thenReturn(new User("admin"));

        HTTPBasicAuthenticator basicAuthenticator = new HTTPBasicAuthenticator(Settings.EMPTY, null);
        AuthDomain basicAuthDomain = new AuthDomain(mockBackend, basicAuthenticator, false, 0);

        DynamicConfigModel mockDcm = mock(DynamicConfigModel.class);
        when(mockDcm.isAnonymousAuthenticationEnabled()).thenReturn(false);
        when(mockDcm.getRestAuthDomains()).thenReturn(new TreeSet<>(List.of(basicAuthDomain)));
        when(mockDcm.getRestAuthorizers()).thenReturn(Collections.emptySet());
        when(mockDcm.getIpAuthFailureListeners()).thenReturn(Collections.emptyList());
        when(mockDcm.getAuthBackendFailureListeners()).thenReturn(ImmutableMultimap.of());
        when(mockDcm.getIpClientBlockRegistries()).thenReturn(Collections.emptyList());
        when(mockDcm.getAuthBackendClientBlockRegistries()).thenReturn(ImmutableMultimap.of());
        when(mockDcm.getHostsResolverMode()).thenReturn("ip-only");

        backendRegistry.onDynamicConfigModelChanged(mockDcm);

        String credentials = "admin:admin";
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        Map<String, String> headers = new HashMap<>();
        headers.put("authorization", "Basic " + base64Credentials);

        GrpcRequestChannel request = createTestRequest(headers);
        boolean result = backendRegistry.authenticate(request);

        assertTrue("Authentication should succeed with valid Basic Auth and configured domain", result);
        assertFalse("Should not have queued an error response", request.getQueuedResponse().isPresent());
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
