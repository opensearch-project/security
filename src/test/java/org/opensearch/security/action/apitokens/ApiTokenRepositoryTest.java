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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.user.User;
import org.opensearch.security.util.ActionListenerUtils.TestActionListener;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked")
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

        doAnswer(invocation -> {
            ActionListener<Void> listener = invocation.getArgument(1);
            listener.onResponse(null);
            return null;
        }).when(apiTokenIndexHandler).deleteToken(eq(tokenName), any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.deleteApiToken(tokenName, listener);

        listener.assertSuccess();
        verify(apiTokenIndexHandler).deleteToken(eq(tokenName), any(ActionListener.class));
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

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(expectedTokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        TestActionListener<Map<String, ApiToken>> listener = new TestActionListener<>();
        repository.getApiTokens(listener);

        Map<String, ApiToken> result = listener.assertSuccess();
        assertThat(result, equalTo(expectedTokens));
        verify(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));
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

        doAnswer(invocation -> {
            ActionListener<Void> listener = invocation.getArgument(1);
            listener.onResponse(null);
            return null;
        }).when(apiTokenIndexHandler).indexTokenMetadata(any(ApiToken.class), any(ActionListener.class));

        TestActionListener<String> listener = new TestActionListener<String>() {
            @Override
            public void onResponse(String result) {
                try {
                    assertThat(result, equalTo(completeToken));
                    verify(apiTokenIndexHandler).createApiTokenIndexIfAbsent();
                    verify(securityTokenManager).issueApiToken(any(), any());
                    verify(apiTokenIndexHandler).indexTokenMetadata(
                        argThat(
                            token -> token.getName().equals(tokenName)
                                && token.getClusterPermissions().equals(clusterPermissions)
                                && token.getIndexPermissions().equals(indexPermissions)
                                && token.getExpiration().equals(expiration)
                        ),
                        any(ActionListener.class)
                    );
                } finally {
                    super.onResponse(result);
                }
            }
        };

        repository.createApiToken(tokenName, clusterPermissions, indexPermissions, expiration, listener);
        listener.assertSuccess();
    }

    @Test
    public void testGetApiTokensThrowsIndexNotFoundException() {
        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onFailure(new IndexNotFoundException("test-index"));
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        TestActionListener<Map<String, ApiToken>> listener = new TestActionListener<>();
        repository.getApiTokens(listener);

        Exception e = listener.assertException(IndexNotFoundException.class);
        assertThat(e.getMessage(), containsString("test-index"));
    }

    @Test
    public void testDeleteApiTokenThrowsApiTokenException() {
        String tokenName = "test-token";

        doAnswer(invocation -> {
            ActionListener<Void> listener = invocation.getArgument(1);
            listener.onFailure(new ApiTokenException("Token not found"));
            return null;
        }).when(apiTokenIndexHandler).deleteToken(eq(tokenName), any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.deleteApiToken(tokenName, listener);

        Exception e = listener.assertException(ApiTokenException.class);
        assertThat(e.getMessage(), containsString("Token not found"));
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

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(Collections.emptyMap());
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        repository.reloadApiTokensFromIndex();

        await().atMost(5, TimeUnit.SECONDS)
            .untilAsserted(() -> assertTrue("Jtis should be empty after clear", repository.getJtis().isEmpty()));
    }

    @Test
    public void testReloadApiTokensFromIndexAndParse() throws IOException {
        // Setup mock response
        Map<String, ApiToken> expectedTokens = Map.of("test", new ApiToken("test", List.of("cluster:monitor"), List.of(), Long.MAX_VALUE));

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(expectedTokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        // Execute the reload
        repository.reloadApiTokensFromIndex();

        // Wait for and verify the async updates
        await().atMost(5, TimeUnit.SECONDS).untilAsserted(() -> {
            assertFalse("Jtis should not be empty after reload", repository.getJtis().isEmpty());
            assertEquals("Should have one JTI entry", 1, repository.getJtis().size());
            assertTrue("Should contain testJti", repository.getJtis().containsKey("test"));
            assertEquals("Should have one cluster action", List.of("cluster:monitor"), repository.getJtis().get("test").getClusterPerm());
            assertEquals("Should have no index actions", List.of(), repository.getJtis().get("test").getIndexPermission());
        });
    }
}
