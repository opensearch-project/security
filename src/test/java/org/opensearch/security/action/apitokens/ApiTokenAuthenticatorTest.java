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

import io.jsonwebtoken.ExpiredJwtException;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
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

    private ThreadContext threadcontext;

    @Before
    public void setUp() {
        Settings settings = Settings.builder()
            .put("enabled", "true")
            .put("signing_key", "U3VwZXJTZWNyZXRLZXlUaGF0SXNFeGFjdGx5NjRCeXRlc0xvbmdBbmRXaWxsV29ya1dpdGhIUzUxMkFsZ29yaXRobSEhCgo=")
            .put("encryption_key", "MTIzNDU2Nzg5MDEyMzQ1Ng==")
            .build();

        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster");
        authenticator.log = log;
        when(log.isDebugEnabled()).thenReturn(true);
        threadcontext = new ThreadContext(Settings.EMPTY);
    }

    @Test
    public void testAuthenticationFailsWhenJtiNotInCache() {
        String testJti = "test-jti-not-in-cache";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        assertFalse(cache.getJtis().containsKey(testJti));

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/test");

        AuthCredentials credentials = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when JTI is not in allowlist cache", credentials);
    }

    @Test
    public void testExtractCredentialsPassWhenJtiInCache() {
        String testJti =
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXRva2VuIiwiYXVkIjoidGVzdC10b2tlbiIsIm5iZiI6MTczNTMyNjM0NywiaXAiOiJnaGlWTXVnWlBtcHZJMjZIT2hmUTRnaEJ1Qkh0Y2x6c1REYVlxQjVBRklyTkE4SzJCVTdxc2toMVBCOEMzQWpTdVBaREM0THVSM2pjZkdpLzlkU2ZicDBuQTNGMkhtSi9jaDA3cDY2ZWJ6OD0iLCJpc3MiOiJvcGVuc2VhcmNoLWNsdXN0ZXIiLCJleHAiOjIyMTg3NjU2NDMzMCwiaWF0IjoxNzM1MzI2MzQ3LCJjcCI6IjlPS3N4aFRaZ1pmOVN1akprRzFXVWIzVC9RVTZ4YmZTc2hrbllkVUhraHM9In0.kqMSnn5YwhLmeiI_8iIBQ5uhmI52n2MNniAa52Zpfs3TiE_PXKiNbDNs08hNqzGYW772gT7lfvp6kZnFxQ4v2Q";
        String encryptedTestJti =
            "k3JQNRXR57Y4V4W1LNkpEP+QzcDra5+/fFfQrr0Rncr/RhYAnYEDgN9RKcJ2Wmjf63NCQa9+HjeFcn0H2wKhMm7pl9bd3ya9FO+LUD7t9Sih4DOjUt0t7ee4ROC0eRK5glMsKsKQVkuY+YKa6A6dT8bMqmt7kIrer7w8TRENr9J8x41TGb/cDDWDvJLME7QkFzJjMxYDgKNiEevMbOpC8yjIZdK08jPe3Thq+xm+JYruoYeyI5g8QjkJA9ZOs1f6eXTAvPxhseuPqgIKykRE25fuWjl5n9tJ9W+jpl+iET7zzOLXSPEU5UepL/COkVd6xW63Ay72oMOewqveDXzyR8S8LAfgRuKgYZWms7yT37XcGg0c6Y7M62KVPo+1XQ+F+K5bgddkd8G+I9KHf561jIMzBcIodgGRj659954W16D1C92+PF/YWPQoTv2hVK4f60H82ga1YSiz3r9UrFV8d7gLJwtyJT9HNPuXO2VZ7xPhre+n1Wv7No0kH2S/r3nqKK6Bk/kn1ZbAmjLxuw13c95lIir6avlKE7XX4PiQDfcGeAyeXOw/36kLW8wH7kjXWdBspld1AiI4fCOaszNXF+7gcuTxIhECl+mEyrJbMI88EWllq+LbydiOrVLFXXRMiCbvj+VTYjzimgJPp+Vuvg==";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        cache.getJtis().put(encryptedTestJti, null);
        assertTrue(cache.getJtis().containsKey(encryptedTestJti));

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNotNull("Should not be null when JTI is in allowlist cache", ac);
    }

    @Test
    public void testExtractCredentialsFailWhenTokenIsExpired() {
        String testJti =
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXRva2VuIiwiYXVkIjoidGVzdC10b2tlbiIsIm5iZiI6MTczNTMyNjU4MiwiaXAiOiJnaGlWTXVnWlBtcHZJMjZIT2hmUTRnaEJ1Qkh0Y2x6c1REYVlxQjVBRklyTkE4SzJCVTdxc2toMVBCOEMzQWpTdVBaREM0THVSM2pjZkdpLzlkU2ZicDBuQTNGMkhtSi9jaDA3cDY2ZWJ6OD0iLCJpc3MiOiJvcGVuc2VhcmNoLWNsdXN0ZXIiLCJleHAiOjI5MDI5NDksImlhdCI6MTczNTMyNjU4MiwiY3AiOiI5T0tzeGhUWmdaZjlTdWpKa0cxV1ViM1QvUVU2eGJmU3Noa25ZZFVIa2hzPSJ9.-f45IAU4jE8EbDuthsPFm-TxtJCk8Q_uRmnG4sEkfLtjmp8mHUbSaS109YRGxKDVr3uEMgFwvkSKEFt7DHhf9A";
        String encryptedTestJti =
            "k3JQNRXR57Y4V4W1LNkpEP+QzcDra5+/fFfQrr0Rncr/RhYAnYEDgN9RKcJ2Wmjf63NCQa9+HjeFcn0H2wKhMm7pl9bd3ya9FO+LUD7t9ShsbOyBUkpFSVuQwrXLatY+glMsKsKQVkuY+YKa6A6dT8bMqmt7kIrer7w8TRENr9J8x41TGb/cDDWDvJLME7QkFzJjMxYDgKNiEevMbOpC8yjIZdK08jPe3Thq+xm+JYruoYeyI5g8QjkJA9ZOs1f6eXTAvPxhseuPqgIKykRE25fuWjl5n9tJ9W+jpl+iET7zzOLXSPEU5UepL/COkVd6xW63Ay72oMOewqveDXzyR8S8LAfgRuKgYZWms7yT37XcGg0c6Y7M62KVPo+1XQ+Fu193YtvS4vqt9G8jHiq51VCRxNHYVlAsratxzvECD8AKBilR9/7dUKyOQDBIzPG4ws+kgI680SgdMgGuLANQPGzal9US8GsWzTbQWCgtObaSVKB02U4gh16wvy3XrXtPz2Z0ZAxoU2Z8opX8hcvB5MG5UUEf+tpgTtVPcbuJyCL42yD3FIc3v/LCYlG/hFvflXBx5c1r+4Tij8Qc/NkYb7/03xiJsVH6eduSqR9M0QBpLm7xg2TgqVMvC/+n96x2V3lS4via4lAK6xuYeRY0ng==";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        cache.getJtis().put(encryptedTestJti, null);
        assertTrue(cache.getJtis().containsKey(encryptedTestJti));

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/test");

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when JTI is expired", ac);
        verify(log).debug(eq("Invalid or expired JWT token."), any(ExpiredJwtException.class));

    }

    @Test
    public void testExtractCredentialsFailWhenIssuerDoesNotMatch() {
        String testJti =
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXRva2VuIiwiYXVkIjoidGVzdC10b2tlbiIsIm5iZiI6MTczNTMyNjM0NywiaXAiOiJnaGlWTXVnWlBtcHZJMjZIT2hmUTRnaEJ1Qkh0Y2x6c1REYVlxQjVBRklyTkE4SzJCVTdxc2toMVBCOEMzQWpTdVBaREM0THVSM2pjZkdpLzlkU2ZicDBuQTNGMkhtSi9jaDA3cDY2ZWJ6OD0iLCJpc3MiOiJvcGVuc2VhcmNoLWNsdXN0ZXIiLCJleHAiOjIyMTg3NjU2NDMzMCwiaWF0IjoxNzM1MzI2MzQ3LCJjcCI6IjlPS3N4aFRaZ1pmOVN1akprRzFXVWIzVC9RVTZ4YmZTc2hrbllkVUhraHM9In0.kqMSnn5YwhLmeiI_8iIBQ5uhmI52n2MNniAa52Zpfs3TiE_PXKiNbDNs08hNqzGYW772gT7lfvp6kZnFxQ4v2Q";
        String encryptedTestJti =
            "k3JQNRXR57Y4V4W1LNkpEP+QzcDra5+/fFfQrr0Rncr/RhYAnYEDgN9RKcJ2Wmjf63NCQa9+HjeFcn0H2wKhMm7pl9bd3ya9FO+LUD7t9Sih4DOjUt0t7ee4ROC0eRK5glMsKsKQVkuY+YKa6A6dT8bMqmt7kIrer7w8TRENr9J8x41TGb/cDDWDvJLME7QkFzJjMxYDgKNiEevMbOpC8yjIZdK08jPe3Thq+xm+JYruoYeyI5g8QjkJA9ZOs1f6eXTAvPxhseuPqgIKykRE25fuWjl5n9tJ9W+jpl+iET7zzOLXSPEU5UepL/COkVd6xW63Ay72oMOewqveDXzyR8S8LAfgRuKgYZWms7yT37XcGg0c6Y7M62KVPo+1XQ+F+K5bgddkd8G+I9KHf561jIMzBcIodgGRj659954W16D1C92+PF/YWPQoTv2hVK4f60H82ga1YSiz3r9UrFV8d7gLJwtyJT9HNPuXO2VZ7xPhre+n1Wv7No0kH2S/r3nqKK6Bk/kn1ZbAmjLxuw13c95lIir6avlKE7XX4PiQDfcGeAyeXOw/36kLW8wH7kjXWdBspld1AiI4fCOaszNXF+7gcuTxIhECl+mEyrJbMI88EWllq+LbydiOrVLFXXRMiCbvj+VTYjzimgJPp+Vuvg==";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        cache.getJtis().put(encryptedTestJti, null);
        assertTrue(cache.getJtis().containsKey(encryptedTestJti));

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/test");

        Settings settings = Settings.builder()
            .put("enabled", "true")
            .put("signing_key", "U3VwZXJTZWNyZXRLZXlUaGF0SXNFeGFjdGx5NjRCeXRlc0xvbmdBbmRXaWxsV29ya1dpdGhIUzUxMkFsZ29yaXRobSEhCgo=")
            .put("encryption_key", "MTIzNDU2Nzg5MDEyMzQ1Ng==")
            .build();

        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster-name-mismatch");
        authenticator.log = log;

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when issuer does not match cluster", ac);
        verify(log).error(eq("The issuer of this api token does not match the current cluster identifier"));
    }

    @Test
    public void testExtractCredentialsFailWhenAccessingRestrictedEndpoint() {
        String testJti =
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXRva2VuIiwiYXVkIjoidGVzdC10b2tlbiIsIm5iZiI6MTczNTMyNjM0NywiaXAiOiJnaGlWTXVnWlBtcHZJMjZIT2hmUTRnaEJ1Qkh0Y2x6c1REYVlxQjVBRklyTkE4SzJCVTdxc2toMVBCOEMzQWpTdVBaREM0THVSM2pjZkdpLzlkU2ZicDBuQTNGMkhtSi9jaDA3cDY2ZWJ6OD0iLCJpc3MiOiJvcGVuc2VhcmNoLWNsdXN0ZXIiLCJleHAiOjIyMTg3NjU2NDMzMCwiaWF0IjoxNzM1MzI2MzQ3LCJjcCI6IjlPS3N4aFRaZ1pmOVN1akprRzFXVWIzVC9RVTZ4YmZTc2hrbllkVUhraHM9In0.kqMSnn5YwhLmeiI_8iIBQ5uhmI52n2MNniAa52Zpfs3TiE_PXKiNbDNs08hNqzGYW772gT7lfvp6kZnFxQ4v2Q";
        String encryptedTestJti =
            "k3JQNRXR57Y4V4W1LNkpEP+QzcDra5+/fFfQrr0Rncr/RhYAnYEDgN9RKcJ2Wmjf63NCQa9+HjeFcn0H2wKhMm7pl9bd3ya9FO+LUD7t9Sih4DOjUt0t7ee4ROC0eRK5glMsKsKQVkuY+YKa6A6dT8bMqmt7kIrer7w8TRENr9J8x41TGb/cDDWDvJLME7QkFzJjMxYDgKNiEevMbOpC8yjIZdK08jPe3Thq+xm+JYruoYeyI5g8QjkJA9ZOs1f6eXTAvPxhseuPqgIKykRE25fuWjl5n9tJ9W+jpl+iET7zzOLXSPEU5UepL/COkVd6xW63Ay72oMOewqveDXzyR8S8LAfgRuKgYZWms7yT37XcGg0c6Y7M62KVPo+1XQ+F+K5bgddkd8G+I9KHf561jIMzBcIodgGRj659954W16D1C92+PF/YWPQoTv2hVK4f60H82ga1YSiz3r9UrFV8d7gLJwtyJT9HNPuXO2VZ7xPhre+n1Wv7No0kH2S/r3nqKK6Bk/kn1ZbAmjLxuw13c95lIir6avlKE7XX4PiQDfcGeAyeXOw/36kLW8wH7kjXWdBspld1AiI4fCOaszNXF+7gcuTxIhECl+mEyrJbMI88EWllq+LbydiOrVLFXXRMiCbvj+VTYjzimgJPp+Vuvg==";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        cache.getJtis().put(encryptedTestJti, null);
        assertTrue(cache.getJtis().containsKey(encryptedTestJti));

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/_plugins/_security/api/apitokens");

        AuthCredentials ac = authenticator.extractCredentials(request, threadcontext);

        assertNull("Should return null when JTI is being used to access restricted endpoint", ac);
        verify(log).error("OpenSearchException[Api Tokens are not allowed to be used for accessing this endpoint.]");

    }

    @Test
    public void testAuthenticatorNotEnabled() {
        String encryptedTestJti =
            "k3JQNRXR57Y4V4W1LNkpEP+QzcDra5+/fFfQrr0Rncr/RhYAnYEDgN9RKcJ2Wmjf63NCQa9+HjeFcn0H2wKhMm7pl9bd3ya9FO+LUD7t9Sih4DOjUt0t7ee4ROC0eRK5glMsKsKQVkuY+YKa6A6dT8bMqmt7kIrer7w8TRENr9J8x41TGb/cDDWDvJLME7QkFzJjMxYDgKNiEevMbOpC8yjIZdK08jPe3Thq+xm+JYruoYeyI5g8QjkJA9ZOs1f6eXTAvPxhseuPqgIKykRE25fuWjl5n9tJ9W+jpl+iET7zzOLXSPEU5UepL/COkVd6xW63Ay72oMOewqveDXzyR8S8LAfgRuKgYZWms7yT37XcGg0c6Y7M62KVPo+1XQ+F+K5bgddkd8G+I9KHf561jIMzBcIodgGRj659954W16D1C92+PF/YWPQoTv2hVK4f60H82ga1YSiz3r9UrFV8d7gLJwtyJT9HNPuXO2VZ7xPhre+n1Wv7No0kH2S/r3nqKK6Bk/kn1ZbAmjLxuw13c95lIir6avlKE7XX4PiQDfcGeAyeXOw/36kLW8wH7kjXWdBspld1AiI4fCOaszNXF+7gcuTxIhECl+mEyrJbMI88EWllq+LbydiOrVLFXXRMiCbvj+VTYjzimgJPp+Vuvg==";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        cache.getJtis().put(encryptedTestJti, null);
        assertTrue(cache.getJtis().containsKey(encryptedTestJti));

        SecurityRequest request = mock(SecurityRequest.class);

        Settings settings = Settings.builder()
            .put("enabled", "false")
            .put("signing_key", "U3VwZXJTZWNyZXRLZXlUaGF0SXNFeGFjdGx5NjRCeXRlc0xvbmdBbmRXaWxsV29ya1dpdGhIUzUxMkFsZ29yaXRobSEhCgo=")
            .put("encryption_key", "MTIzNDU2Nzg5MDEyMzQ1Ng==")
            .build();
        ThreadContext threadContext = new ThreadContext(settings);

        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster-name-mismatch");
        authenticator.log = log;

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        assertNull("Should return null when api tokens auth is not enabled", ac);
        verify(log).error(eq("Api token authentication is disabled"));
    }
}
