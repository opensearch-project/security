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
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import javax.net.ssl.SSLEngine;

import com.google.common.collect.ImmutableMultimap;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.http.HTTPBasicAuthenticator;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensearch.security.auth.http.saml.HTTPSamlAuthenticator.SAML_TYPE;

public class BackendRegistryTest {

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
        when(adminDns.isAdmin(any())).thenReturn(false);
        when(adminDns.isAdminDN(any())).thenReturn(false);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(clusterInfoHolder.hasClusterManager()).thenReturn(true);
        when(xffResolver.resolve(any())).thenReturn(new TransportAddress(new InetSocketAddress("127.0.0.1", 9200)));

        backendRegistry = new BackendRegistry(Settings.EMPTY, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);
    }

    @Test
    public void testFailedBasicLoginBeforeSamlChallengeLogsFailedLogin() throws Exception {
        AuthDomain basicAuthDomain = basicAuthDomain(rejectingBackend(), false, 1);
        AuthDomain samlAuthDomain = samlAuthDomain(2);
        configureAuthDomains(basicAuthDomain, samlAuthDomain);

        TestSecurityRequestChannel request = requestWithBasicAuth("testuser", "wrong-password");
        boolean authenticated = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail when Basic Auth backend rejects credentials", authenticated);
        assertTrue("SAML challenge should queue a redirect response", request.getQueuedResponse().isPresent());
        assertEquals("SAML challenge should return redirect response", 302, request.getQueuedResponse().get().getStatus());
        verify(auditLog).logFailedLogin(eq("testuser"), eq(false), isNull(), same(request));
    }

    @Test
    public void testSamlRedirectWithoutCredentialsDoesNotLogFailedLogin() {
        AuthDomain samlAuthDomain = samlAuthDomain(1);
        configureAuthDomains(samlAuthDomain);

        TestSecurityRequestChannel request = new TestSecurityRequestChannel(Collections.emptyMap());
        boolean authenticated = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail while SAML redirects", authenticated);
        assertTrue("SAML challenge should queue a redirect response", request.getQueuedResponse().isPresent());
        assertEquals("SAML challenge should return redirect response", 302, request.getQueuedResponse().get().getStatus());
        verify(auditLog, never()).logFailedLogin(any(), anyBoolean(), any(), any());
    }

    @Test
    public void testNonSamlChallengeWithoutCredentialsLogsFailedLogin() {
        AuthDomain basicAuthDomain = basicAuthDomain(rejectingBackend(), true, 1);
        configureAuthDomains(basicAuthDomain);

        TestSecurityRequestChannel request = new TestSecurityRequestChannel(Collections.emptyMap());
        boolean authenticated = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail when Basic Auth credentials are missing", authenticated);
        assertTrue("Basic Auth challenge should queue a response", request.getQueuedResponse().isPresent());
        assertEquals("Basic Auth challenge should return unauthorized response", 401, request.getQueuedResponse().get().getStatus());
        verify(auditLog).logFailedLogin(eq("<NONE>"), eq(false), isNull(), same(request));
    }

    @Test
    public void testValidBasicLoginBeforeSamlChallengeDoesNotLogFailedLogin() throws Exception {
        AuthDomain basicAuthDomain = basicAuthDomain(acceptingBackend("testuser"), false, 1);
        AuthDomain samlAuthDomain = samlAuthDomain(2);
        configureAuthDomains(basicAuthDomain, samlAuthDomain);

        TestSecurityRequestChannel request = requestWithBasicAuth("testuser", "correct-password");
        boolean authenticated = backendRegistry.authenticate(request);

        assertTrue("Authentication should succeed when Basic Auth backend accepts credentials", authenticated);
        assertFalse("Successful authentication should not queue a challenge response", request.getQueuedResponse().isPresent());
        verify(auditLog, never()).logFailedLogin(any(), anyBoolean(), any(), any());
    }

    @Test
    public void testFinalFailureWithoutChallengeLogsFailedLoginWithRejectedUsername() throws Exception {
        AuthDomain basicAuthDomain = basicAuthDomain(rejectingBackend(), false, 1);
        configureAuthDomains(basicAuthDomain);

        TestSecurityRequestChannel request = requestWithBasicAuth("testuser", "wrong-password");
        boolean authenticated = backendRegistry.authenticate(request);

        assertFalse("Authentication should fail when no auth domain accepts credentials", authenticated);
        assertTrue("Final failure should queue an unauthorized response", request.getQueuedResponse().isPresent());
        assertEquals("Final failure should return unauthorized response", 401, request.getQueuedResponse().get().getStatus());
        verify(auditLog).logFailedLogin(eq("testuser"), eq(false), isNull(), same(request));
    }

    private void configureAuthDomains(AuthDomain... authDomains) {
        DynamicConfigModel dcm = mock(DynamicConfigModel.class);
        when(dcm.isAnonymousAuthenticationEnabled()).thenReturn(false);
        when(dcm.getRestAuthDomains()).thenReturn(new TreeSet<>(List.of(authDomains)));
        when(dcm.getRestAuthorizers()).thenReturn(Collections.emptySet());
        when(dcm.getIpAuthFailureListeners()).thenReturn(Collections.emptyList());
        when(dcm.getAuthBackendFailureListeners()).thenReturn(ImmutableMultimap.of());
        when(dcm.getIpClientBlockRegistries()).thenReturn(Collections.emptyList());
        when(dcm.getAuthBackendClientBlockRegistries()).thenReturn(ImmutableMultimap.of());
        when(dcm.getHostsResolverMode()).thenReturn("ip-only");

        backendRegistry.onDynamicConfigModelChanged(dcm);
    }

    private AuthDomain basicAuthDomain(AuthenticationBackend backend, boolean challenge, int order) {
        return new AuthDomain(backend, new HTTPBasicAuthenticator(Settings.EMPTY, null), challenge, order);
    }

    private AuthDomain samlAuthDomain(int order) {
        HTTPAuthenticator samlAuthenticator = mock(HTTPAuthenticator.class);
        when(samlAuthenticator.getType()).thenReturn(SAML_TYPE);
        when(samlAuthenticator.reRequestAuthentication(any(), nullable(AuthCredentials.class))).thenReturn(
            Optional.of(new SecurityResponse(302, Map.of("Location", "/saml"), "Redirect"))
        );
        return new AuthDomain(rejectingBackend(), samlAuthenticator, true, order);
    }

    private AuthenticationBackend acceptingBackend(String username) throws Exception {
        AuthenticationBackend backend = mock(AuthenticationBackend.class);
        when(backend.getType()).thenReturn("internal");
        when(backend.authenticate(any())).thenReturn(new User(username));
        return backend;
    }

    private AuthenticationBackend rejectingBackend() {
        AuthenticationBackend backend = mock(AuthenticationBackend.class);
        when(backend.getType()).thenReturn("internal");
        when(backend.authenticate(any())).thenThrow(new OpenSearchSecurityException("Invalid credentials"));
        return backend;
    }

    private TestSecurityRequestChannel requestWithBasicAuth(String username, String password) {
        String credentials = username + ":" + password;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return new TestSecurityRequestChannel(Map.of("Authorization", "Basic " + encodedCredentials));
    }

    private static class TestSecurityRequestChannel implements SecurityRequestChannel {

        private final Map<String, List<String>> headers;
        private final InetSocketAddress remoteAddress = new InetSocketAddress("127.0.0.1", 9200);
        private SecurityResponse queuedResponse;

        TestSecurityRequestChannel(Map<String, String> headers) {
            this.headers = new HashMap<>();
            for (Map.Entry<String, String> header : headers.entrySet()) {
                this.headers.put(header.getKey(), List.of(header.getValue()));
            }
        }

        @Override
        public Map<String, List<String>> getHeaders() {
            return headers;
        }

        @Override
        public SSLEngine getSSLEngine() {
            return null;
        }

        @Override
        public String path() {
            return "/";
        }

        @Override
        public RestRequest.Method method() {
            return RestRequest.Method.GET;
        }

        @Override
        public Optional<InetSocketAddress> getRemoteAddress() {
            return Optional.of(remoteAddress);
        }

        @Override
        public String uri() {
            return "/";
        }

        @Override
        public Map<String, String> params() {
            return Collections.emptyMap();
        }

        @Override
        public Set<String> getUnconsumedParams() {
            return Collections.emptySet();
        }

        @Override
        public void queueForSending(SecurityResponse response) {
            queuedResponse = response;
        }

        @Override
        public Optional<SecurityResponse> getQueuedResponse() {
            return Optional.ofNullable(queuedResponse);
        }
    }
}
