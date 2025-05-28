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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.http.ApiTokenAuthenticator;
import org.opensearch.security.user.AuthCredentials;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.any;
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

    private ThreadContext threadcontext;
    private final String signingKey = Base64.getEncoder()
        .encodeToString("jwt signing key long enough for secure api token authentication testing".getBytes(StandardCharsets.UTF_8));
    private final String tokenName = "test-token";

    @Before
    public void setUp() {
        Settings settings = Settings.builder().put("enabled", "true").put("signing_key", signingKey).build();

        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster", apiTokenRepository);
        authenticator.log = log;
        when(log.isDebugEnabled()).thenReturn(true);
        threadcontext = new ThreadContext(Settings.EMPTY);
    }

    @Test
    public void testAuthenticationFailsWhenJtiNotInCache() {
        String testJti = "test-jti-not-in-cache";

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/test");

        AuthCredentials credentials = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when JTI is not in allowlist cache", credentials);
    }

    @Test
    public void testExtractCredentialsPassWhenJtiInCache() {
        String token = Jwts.builder()
            .setIssuer("opensearch-cluster")
            .setSubject(tokenName)
            .setAudience(tokenName)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
            .signWith(SignatureAlgorithm.HS512, signingKey)
            .compact();

        when(apiTokenRepository.isValidToken("token:" + tokenName)).thenReturn(true);

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + token);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNotNull("Should not be null when JTI is in allowlist cache", ac);
    }

    @Test
    public void testExtractCredentialsFailWhenTokenIsExpired() {
        String token = Jwts.builder()
            .setIssuer("opensearch-cluster")
            .setSubject(tokenName)
            .setAudience(tokenName)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().minus(1, ChronoUnit.DAYS)))
            .signWith(SignatureAlgorithm.HS512, signingKey)
            .compact();

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + token);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when JTI is expired", ac);
        verify(log).debug(eq("Invalid or expired api token."), any(ExpiredJwtException.class));

    }

    @Test
    public void testExtractCredentialsFailWhenIssuerDoesNotMatch() {
        String token = Jwts.builder()
            .setIssuer("not-opensearch-cluster")
            .setSubject(tokenName)
            .setAudience(tokenName)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
            .signWith(SignatureAlgorithm.HS512, signingKey)
            .compact();

        when(apiTokenRepository.isValidToken("token:" + tokenName)).thenReturn(true);

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + token);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when issuer does not match cluster", ac);
        verify(log).error(eq("The issuer of this api token does not match the current cluster identifier"));
    }

    @Test
    public void testExtractCredentialsFailWhenAccessingRestrictedEndpoint() {
        String token = Jwts.builder()
            .setIssuer("opensearch-cluster")
            .setSubject(tokenName)
            .setAudience(tokenName)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
            .signWith(SignatureAlgorithm.HS512, signingKey)
            .compact();

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + token);
        when(request.path()).thenReturn("/_plugins/_security/api/apitokens");

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when JTI is being used to access restricted endpoint", ac);
        verify(log).error("OpenSearchException[Api Tokens are not allowed to be used for accessing this endpoint.]");
    }

    @Test
    public void testAuthenticatorNotEnabled() {
        String token = Jwts.builder()
            .setIssuer("opensearch-cluster")
            .setSubject(tokenName)
            .setAudience(tokenName)
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
            .signWith(SignatureAlgorithm.HS512, signingKey)
            .compact();

        SecurityRequest request = mock(SecurityRequest.class);

        Settings settings = Settings.builder()
            .put("enabled", "false")
            .put("signing_key", "U3VwZXJTZWNyZXRLZXlUaGF0SXNFeGFjdGx5NjRCeXRlc0xvbmdBbmRXaWxsV29ya1dpdGhIUzUxMkFsZ29yaXRobSEhCgo=")
            .build();
        ThreadContext threadContext = new ThreadContext(settings);

        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster", apiTokenRepository);
        authenticator.log = log;

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        assertNull("Should return null when api tokens auth is not enabled", ac);
        verify(log).error(eq("Api token authentication is disabled"));
    }
}
