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
import java.time.Instant;
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
import org.opensearch.security.securityconf.impl.v7.RoleV7;
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
        User apiTokenNotExists = new User("token:notexists");
        User apiTokenExists = new User("token:exists");
        RoleV7 all = new RoleV7();
        RoleV7.Index allIndices = new RoleV7.Index();
        allIndices.setAllowed_actions(List.of("*"));
        allIndices.setIndex_patterns(List.of("*"));
        all.setCluster_permissions(List.of("cluster_all"));
        all.setIndex_permissions(List.of(allIndices));
        repository.getJtis().put("exists", all);

        RoleV7 permissionsForDerek = repository.getApiTokenPermissionsForUser(derek);
        assertEquals(List.of(), permissionsForDerek.getCluster_permissions());
        assertEquals(List.of(), permissionsForDerek.getIndex_permissions());

        RoleV7 permissionsForApiTokenNotExists = repository.getApiTokenPermissionsForUser(apiTokenNotExists);
        assertEquals(List.of(), permissionsForApiTokenNotExists.getCluster_permissions());
        assertEquals(List.of(), permissionsForApiTokenNotExists.getIndex_permissions());

        RoleV7 permissionsForApiTokenExists = repository.getApiTokenPermissionsForUser(apiTokenExists);
        assertEquals(List.of("cluster_all"), permissionsForApiTokenExists.getCluster_permissions());
        assertEquals(List.of("*"), permissionsForApiTokenExists.getIndex_permissions().get(0).getAllowed_actions());
        assertEquals(List.of("*"), permissionsForApiTokenExists.getIndex_permissions().get(0).getIndex_patterns());
    }

    @Test
    public void testGetApiTokens() throws IndexNotFoundException {
        Map<String, ApiToken> expectedTokens = new HashMap<>();
        expectedTokens.put("token1", new ApiToken("token1", Arrays.asList("perm1"), Arrays.asList(), Instant.now(), Long.MAX_VALUE));

        doAnswer(invocation -> {
            ActionListener<?> listener = invocation.getArgument(0);
            listener.onResponse(null);
            return null;
        }).when(apiTokenIndexHandler).createApiTokenIndexIfAbsent(any(ActionListener.class));

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
                    verify(apiTokenIndexHandler).createApiTokenIndexIfAbsent(any());
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

        doAnswer(invocation -> {
            ActionListener<?> l = invocation.getArgument(0);
            l.onResponse(null);
            return null;
        }).when(apiTokenIndexHandler).createApiTokenIndexIfAbsent(any(ActionListener.class));

        repository.createApiToken(tokenName, clusterPermissions, indexPermissions, expiration, listener);
        listener.assertSuccess();
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
        RoleV7 testRole = new RoleV7();
        RoleV7.Index none = new RoleV7.Index();
        none.setAllowed_actions(List.of(""));
        none.setIndex_patterns(List.of(""));
        testRole.setCluster_permissions(List.of("read"));
        testRole.setIndex_permissions(List.of(none));

        repository.getJtis().put(jti, testRole);
        assertEquals("Should retrieve correct permissions", testRole, repository.getJtis().get(jti));

        repository.getJtis().remove(jti);
        assertNull("Should return null after removal", repository.getJtis().get(jti));
    }

    @Test
    public void testClearJtis() {
        RoleV7 testRole = new RoleV7();
        RoleV7.Index none = new RoleV7.Index();
        none.setAllowed_actions(List.of(""));
        none.setIndex_patterns(List.of(""));
        testRole.setCluster_permissions(List.of("read"));
        testRole.setIndex_permissions(List.of(none));
        repository.getJtis().put("testJti", testRole);

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(Collections.emptyMap());
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        repository.reloadApiTokensFromIndex(ActionListener.wrap(() -> {
            await().atMost(5, TimeUnit.SECONDS)
                .untilAsserted(() -> assertTrue("Jtis should be empty after clear", repository.getJtis().isEmpty()));
        }));
    }

    @Test
    public void testReloadApiTokensFromIndexAndParse() throws IOException {
        // Setup mock response
        Map<String, ApiToken> expectedTokens = Map.of(
            "test",
            new ApiToken("test", List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE)
        );

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(expectedTokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        // Execute the reload
        repository.reloadApiTokensFromIndex(ActionListener.wrap(() -> {
            // Wait for and verify the async updates
            await().atMost(5, TimeUnit.SECONDS).untilAsserted(() -> {
                assertFalse("Jtis should not be empty after reload", repository.getJtis().isEmpty());
                assertEquals("Should have one JTI entry", 1, repository.getJtis().size());
                assertTrue("Should contain testJti", repository.getJtis().containsKey("test"));
                assertEquals(
                    "Should have one cluster action",
                    List.of("cluster:monitor"),
                    repository.getJtis().get("test").getCluster_permissions()
                );
                assertEquals("Should have no index actions", List.of(), repository.getJtis().get("test").getIndex_permissions());
            });
        }));
    }
}
