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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;

import org.mockito.Mock;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApiTokenRepositoryTest {
    @Mock
    private SecurityTokenManager securityTokenManager;

    @Mock
    private ApiTokenIndexHandler apiTokenIndexHandler;

    private ApiTokenRepository repository;

    @Before
    public void setUp() {
        apiTokenIndexHandler = mock(ApiTokenIndexHandler.class);
        securityTokenManager = mock(SecurityTokenManager.class);
        repository = new ApiTokenRepository(apiTokenIndexHandler, securityTokenManager);
    }

    @Test
    public void testDeleteApiToken() throws ApiTokenException {
        String tokenName = "test-token";

        repository.deleteApiToken(tokenName);

        verify(apiTokenIndexHandler).deleteToken(tokenName);
    }

    @Test
    public void testGetApiTokens() throws IndexNotFoundException {
        Map<String, ApiToken> expectedTokens = new HashMap<>();
        expectedTokens.put("token1", new ApiToken("token1", Arrays.asList("perm1"), Arrays.asList(), Long.MAX_VALUE));
        when(apiTokenIndexHandler.getTokenMetadatas()).thenReturn(expectedTokens);

        Map<String, ApiToken> result = repository.getApiTokens();

        assertThat(result, equalTo(expectedTokens));
        verify(apiTokenIndexHandler).getTokenMetadatas();
    }

    @Test
    public void testCreateApiToken() {
        String tokenName = "test-token";
        List<String> clusterPermissions = Arrays.asList("cluster:admin");
        List<ApiToken.IndexPermission> indexPermissions = Arrays.asList(
            new ApiToken.IndexPermission(Arrays.asList("test-*"), Arrays.asList("read"))
        );
        Long expiration = 3600L;

        String completeToken = "complete-token";
        String encryptedToken = "encrypted-token";
        ExpiringBearerAuthToken bearerToken = mock(ExpiringBearerAuthToken.class);
        when(bearerToken.getCompleteToken()).thenReturn(completeToken);
        when(securityTokenManager.issueApiToken(any())).thenReturn(bearerToken);
        when(securityTokenManager.encryptToken(completeToken)).thenReturn(encryptedToken);

        String result = repository.createApiToken(tokenName, clusterPermissions, indexPermissions, expiration);

        verify(apiTokenIndexHandler).createApiTokenIndexIfAbsent();
        verify(securityTokenManager).issueApiToken(any(ApiToken.class));
        verify(securityTokenManager).encryptToken(completeToken);
        verify(apiTokenIndexHandler).indexTokenMetadata(
            argThat(
                token -> token.getName().equals(tokenName)
                    && token.getJti().equals(encryptedToken)
                    && token.getClusterPermissions().equals(clusterPermissions)
                    && token.getIndexPermissions().equals(indexPermissions)
            )
        );
        assertThat(result, equalTo(completeToken));
    }

    @Test(expected = IndexNotFoundException.class)
    public void testGetApiTokensThrowsIndexNotFoundException() throws IndexNotFoundException {
        when(apiTokenIndexHandler.getTokenMetadatas()).thenThrow(new IndexNotFoundException("test-index"));

        repository.getApiTokens();

    }

    @Test(expected = ApiTokenException.class)
    public void testDeleteApiTokenThrowsApiTokenException() throws ApiTokenException {
        String tokenName = "test-token";
        doThrow(new ApiTokenException("Token not found")).when(apiTokenIndexHandler).deleteToken(tokenName);

        repository.deleteApiToken(tokenName);
    }
}
