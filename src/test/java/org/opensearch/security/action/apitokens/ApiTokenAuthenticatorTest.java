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

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.http.ApiTokenAuthenticator;
import org.opensearch.security.user.AuthCredentials;

import org.mockito.Mock;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ApiTokenAuthenticatorTest {

    private ApiTokenAuthenticator authenticator;
    private ApiTokenIndexListenerCache cache;
    private String testJti = "test-jti";
    @Mock
    private Logger log;

    @Before
    public void setUp() {
        // Setup basic settings
        Settings settings = Settings.builder()
            .put("enabled", "true")
            .put("signing_key", "U3VwZXJTZWNyZXRLZXlUaGF0SXNFeGFjdGx5NjRCeXRlc0xvbmdBbmRXaWxsV29ya1dpdGhIUzUxMkFsZ29yaXRobSEhCgo=")
            .put("encryption_key", "MTIzNDU2Nzg5MDEyMzQ1Ng==")
            .build();

        authenticator = new ApiTokenAuthenticator(settings, "opensearch-cluster");
        cache = ApiTokenIndexListenerCache.getInstance();
    }

    @Test
    public void testAuthenticationFailsWhenJtiNotInCache() {
        String testJti = "test-jti-not-in-cache";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        assertFalse(cache.getJtis().contains(testJti));

        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/test");

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);

        AuthCredentials credentials = authenticator.extractCredentials(request, threadContext);

        // It should return null when JTI is not in cache
        assertNull("Should return null when JTI is not in allowlist cache", credentials);
    }

    @Test
    public void testExtractCredentialsPassWhenJtiInCache() {
        // Given: A JTI that is in the cache
        String testJti =
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXRva2VuIiwiYXVkIjoidGVzdC10b2tlbiIsIm5iZiI6MTczNTMxODI5NywiaXAiOiJnaGlWTXVnWlBtcHZJMjZIT2hmUTRnaEJ1Qkh0Y2x6c1REYVlxQjVBRklyTkE4SzJCVTdxc2toMVBCOEMzQWpTdVBaREM0THVSM2pjZkdpLzlkU2ZicDBuQTNGMkhtSi9jaDA3cDY2ZWJ6OD0iLCJpc3MiOiJvcGVuc2VhcmNoLWNsdXN0ZXIiLCJleHAiOjE3Mzc5MTAyOTcsImlhdCI6MTczNTMxODI5NywiY3AiOiI5T0tzeGhUWmdaZjlTdWpKa0cxV1ViM1QvUVU2eGJmU3Noa25ZZFVIa2hzPSJ9.xdoDZiGBbqaqcH2evoMEV5384oTyRg04_gO3akQpO4c502c8bV8W5TF_5SxUvkXKDeuQEBFH-4c44VVhCnUQIw";
        String encryptedTestJti =
            "k3JQNRXR57Y4V4W1LNkpEP+QzcDra5+/fFfQrr0Rncr/RhYAnYEDgN9RKcJ2Wmjf63NCQa9+HjeFcn0H2wKhMm7pl9bd3ya9FO+LUD7t9Sj+IKBsThVo93sUmnxJh/llglMsKsKQVkuY+YKa6A6dT8bMqmt7kIrer7w8TRENr9J8x41TGb/cDDWDvJLME7QkFzJjMxYDgKNiEevMbOpC8yjIZdK08jPe3Thq+xm+JYruoYeyI5g8QjkJA9ZOs1f6eXTAvPxhseuPqgIKykRE25fuWjl5n9tJ9W+jpl+iET7zzOLXSPEU5UepL/COkVd6xW63Ay72oMOewqveDXzyR8S8LAfgRuKgYZWms7yT37XcGg0c6Y7M62KVPo+1XQ+FGLtty3eDKwaSopFqLNcISFMiPml9XYv7V1AndJGINbH4KUDyeSQYUh4d+sOxjg9prGzW0nvKE22jzyQlW9t0wpDiB0visInvKVZAqKLPUp0x0pFbAVV12sJJkw6DFkD6+VL+8d2L/Z8kxJXO3uHHjhO3u3RWAe6UhLGncLhJciH57MEw8zFdNturr+tJREL5WbWyiEzKTOBzO8R5Ec92XyCDshIXzVxQv/QOM5meFxPcrkBAgKa6ztWCCmQqa2M1MdKkwKUGn3w6ixOTZ55nZQ==";
        ApiTokenIndexListenerCache cache = ApiTokenIndexListenerCache.getInstance();
        cache.getJtis().add(encryptedTestJti);
        assertTrue(cache.getJtis().contains(encryptedTestJti));

        // Create a mock request with the JWT token and path
        SecurityRequest request = mock(SecurityRequest.class);
        when(request.header("Authorization")).thenReturn("Bearer " + testJti);
        when(request.path()).thenReturn("/test");

        // Create ThreadContext
        Settings settings = Settings.builder().build();
        ThreadContext threadContext = new ThreadContext(settings);

        AuthCredentials ac = authenticator.extractCredentials(request, threadContext);

        // Verify the exception message if needed
        assertNotNull("Should return null when JTI is not in allowlist cache", ac);

    }

}
