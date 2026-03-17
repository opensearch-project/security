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

package org.opensearch.security.action.apitokens;

import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.http.ApiTokenAuthenticator;
import org.opensearch.security.user.AuthCredentials;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ApiTokenAuthenticatorTest {

    private ApiTokenAuthenticator authenticator;
    @Mock
    private Logger log;
    @Mock
    private ApiTokenRepository apiTokenRepository;

    private ThreadContext threadContext;
    private final String plainToken = "os_validtoken123";
    private final String tokenHash = ApiTokenRepository.hashToken(plainToken);

    @Before
    public void setUp() {
        Settings settings = Settings.builder().put("enabled", "true").build();
        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster", apiTokenRepository);
        authenticator.log = log;
        threadContext = new ThreadContext(Settings.EMPTY);
    }

    @Test
    public void testExtractCredentialsPassWhenTokenInCache() {
        when(apiTokenRepository.isValidToken(tokenHash)).thenReturn(true);
        when(apiTokenRepository.getTokenMetadata(tokenHash)).thenReturn(
            new ApiTokenRepository.TokenMetadata(new org.opensearch.security.securityconf.impl.v7.RoleV7(), Long.MAX_VALUE)
        );

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("ApiKey " + plainToken);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        assertNotNull("Should return credentials when token is valid", ac);
    }

    @Test
    public void testExtractCredentialsFailWhenTokenNotInCache() {
        when(apiTokenRepository.isValidToken(tokenHash)).thenReturn(false);

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("ApiKey " + plainToken);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        assertNull("Should return null when token is not in cache", ac);
    }

    @Test
    public void testExtractCredentialsFailWhenTokenIsExpired() {
        when(apiTokenRepository.isValidToken(tokenHash)).thenReturn(true);
        when(apiTokenRepository.getTokenMetadata(tokenHash)).thenReturn(
            new ApiTokenRepository.TokenMetadata(new org.opensearch.security.securityconf.impl.v7.RoleV7(), 1L)
        );

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("ApiKey " + plainToken);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        assertNull("Should return null when token is expired", ac);
    }

    @Test
    public void testExtractCredentialsFailWhenTokenMissingPrefix() {
        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("ApiKey notanosprefixedtoken");
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        assertNull("Should return null when token does not have os_ prefix", ac);
    }

    @Test
    public void testExtractCredentialsFailWhenAccessingRestrictedEndpoint() {
        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("ApiKey " + plainToken);
        when(request.path()).thenReturn("/_plugins/_security/api/apitokens");

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        assertNull("Should return null when accessing restricted endpoint", ac);
        verify(log).error("OpenSearchException[Api Tokens are not allowed to be used for accessing this endpoint.]");
    }

    @Test
    public void testAuthenticatorNotEnabled() {
        Settings settings = Settings.builder().put("enabled", "false").build();
        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster", apiTokenRepository);
        authenticator.log = log;

        SecurityRequest request = mock(SecurityRequest.class);

        AuthCredentials ac = authenticator.extractCredentials(request, new ThreadContext(Settings.EMPTY));

        assertNull("Should return null when authenticator is disabled", ac);
        verify(log).error(eq("Api token authentication is disabled"));
    }
}
