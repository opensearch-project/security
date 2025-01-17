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

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.user.User;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
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
        repository = ApiTokenRepository.forTest(apiTokenIndexHandler, securityTokenManager);
    }

    @Test
    public void testDeleteApiToken() throws ApiTokenException {
        String tokenName = "test-token";

        repository.deleteApiToken(tokenName);

        verify(apiTokenIndexHandler).deleteToken(tokenName);
    }

    @Test
    public void testGetApiTokenPermissionsForUser() throws ApiTokenException {
        User derek = new User("derek");
        User apiTokenNotExists = new User("apitoken:notexists");
        User apiTokenExists = new User("apitoken:exists");
        repository.getJtis()
            .put("exists", new Permissions(List.of("cluster_all"), List.of(new ApiToken.IndexPermission(List.of("*"), List.of("*")))));

        Permissions permissionsForDerek = repository.getApiTokenPermissionsForUser(derek);
        assertEquals(List.of(), permissionsForDerek.getClusterPerm());
        assertEquals(List.of(), permissionsForDerek.getIndexPermission());

        Permissions permissionsForApiTokenNotExists = repository.getApiTokenPermissionsForUser(apiTokenNotExists);
        assertEquals(List.of(), permissionsForApiTokenNotExists.getClusterPerm());
        assertEquals(List.of(), permissionsForApiTokenNotExists.getIndexPermission());

        Permissions permissionsForApiTokenExists = repository.getApiTokenPermissionsForUser(apiTokenExists);
        assertEquals(List.of("cluster_all"), permissionsForApiTokenExists.getClusterPerm());
        assertEquals(List.of("*"), permissionsForApiTokenExists.getIndexPermission().getFirst().getAllowedActions());
        assertEquals(List.of("*"), permissionsForApiTokenExists.getIndexPermission().getFirst().getIndexPatterns());

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
        ExpiringBearerAuthToken bearerToken = mock(ExpiringBearerAuthToken.class);
        when(bearerToken.getCompleteToken()).thenReturn(completeToken);
        when(securityTokenManager.issueApiToken(any(), any())).thenReturn(bearerToken);

        String result = repository.createApiToken(tokenName, clusterPermissions, indexPermissions, expiration);

        verify(apiTokenIndexHandler).createApiTokenIndexIfAbsent();
        verify(securityTokenManager).issueApiToken(any(), any());
        verify(apiTokenIndexHandler).indexTokenMetadata(
            argThat(
                token -> token.getName().equals(tokenName)
                    && token.getClusterPermissions().equals(clusterPermissions)
                    && token.getIndexPermissions().equals(indexPermissions)
                    && token.getExpiration().equals(expiration)
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

    @Test
    public void testJtisOperations() {
        String jti = "testJti";
        Permissions permissions = new Permissions(List.of("read"), List.of(new ApiToken.IndexPermission(List.of(), List.of())));

        repository.getJtis().put(jti, permissions);
        assertEquals("Should retrieve correct permissions", permissions, repository.getJtis().get(jti));

        repository.getJtis().remove(jti);
        assertNull("Should return null after removal", repository.getJtis().get(jti));
    }

    @Test
    public void testClearJtis() {
        repository.getJtis().put("testJti", new Permissions(List.of("read"), List.of(new ApiToken.IndexPermission(List.of(), List.of()))));
        repository.reloadApiTokensFromIndex();

        assertTrue("Jtis should be empty after clear", repository.getJtis().isEmpty());
    }

    @Test
    public void testReloadApiTokensFromIndexAndParse() throws IOException {
        when(apiTokenIndexHandler.getTokenMetadatas()).thenReturn(Map.of("test", new ApiToken("test", List.of("cluster:monitor"), List.of(), Long.MAX_VALUE)));

        // Execute the reload
        repository.reloadApiTokensFromIndex();

        // Verify the cache was updated
        assertFalse("Jtis should not be empty after reload", repository.getJtis().isEmpty());
        assertEquals("Should have one JTI entry", 1, repository.getJtis().size());
        assertTrue("Should contain testJti", repository.getJtis().containsKey("test"));
        // Verify extraction works
        assertEquals("Should have one cluster action", List.of("cluster:monitor"), repository.getJtis().get("test").getClusterPerm());
        assertEquals("Should have no index actions", List.of(), repository.getJtis().get("test").getIndexPermission());
    }
}
