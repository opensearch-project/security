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

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class ApiTokenRepositoryTest {
    private static final String TOKEN_ALPHA = "os_alpha";
    private static final String TOKEN_BETA = "os_beta";
    private static final String TOKEN_FRESH = "os_fresh";
    private static final String TOKEN_STALE = "os_stale";
    private static final String TOKEN_ONE = "os_one";
    private static final String TOKEN_TWO = "os_two";
    private static final String TOKEN_THREE = "os_three";
    private static final String TOKEN_TEST = "os_test";
    private static final String TOKEN_EXISTS = "os_exists";

    private static final String HASH_ALPHA = ApiTokenRepository.hashToken(TOKEN_ALPHA);
    private static final String HASH_BETA = ApiTokenRepository.hashToken(TOKEN_BETA);
    private static final String HASH_FRESH = ApiTokenRepository.hashToken(TOKEN_FRESH);
    private static final String HASH_STALE = ApiTokenRepository.hashToken(TOKEN_STALE);
    private static final String HASH_ONE = ApiTokenRepository.hashToken(TOKEN_ONE);
    private static final String HASH_TWO = ApiTokenRepository.hashToken(TOKEN_TWO);
    private static final String HASH_THREE = ApiTokenRepository.hashToken(TOKEN_THREE);
    private static final String HASH_TEST = ApiTokenRepository.hashToken(TOKEN_TEST);
    private static final String HASH_EXISTS = ApiTokenRepository.hashToken(TOKEN_EXISTS);
    @Mock
    private ApiTokenIndexHandler apiTokenIndexHandler;
    private ApiTokenRepository repository;

    @Before
    public void setUp() {
        apiTokenIndexHandler = mock(ApiTokenIndexHandler.class);
        repository = ApiTokenRepository.forTest(apiTokenIndexHandler);
    }

    @Test
    public void testRevokeApiToken() throws ApiTokenException {
        String tokenName = "test-token";

        doAnswer(invocation -> {
            ActionListener<Void> listener = invocation.getArgument(1);
            listener.onResponse(null);
            return null;
        }).when(apiTokenIndexHandler).revokeToken(eq(tokenName), any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.revokeApiToken(tokenName, listener);

        listener.assertSuccess();
        verify(apiTokenIndexHandler).revokeToken(eq(tokenName), any(ActionListener.class));
    }

    @Test
    public void testGetApiTokenPermissionsForUser() throws ApiTokenException {
        User derek = new User("derek");
        User apiTokenNotExists = new User("token:notexists");
        User apiTokenExists = new User("token:" + HASH_EXISTS);
        RoleV7 all = new RoleV7();
        RoleV7.Index allIndices = new RoleV7.Index();
        allIndices.setAllowed_actions(List.of("*"));
        allIndices.setIndex_patterns(List.of("*"));
        all.setCluster_permissions(List.of("cluster_all"));
        all.setIndex_permissions(List.of(allIndices));
        repository.getJtis().put(HASH_EXISTS, all);

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
        expectedTokens.put(
            HASH_TEST,
            new ApiToken("token1", HASH_TEST, Arrays.asList("perm1"), Arrays.asList(), Instant.now(), Long.MAX_VALUE)
        );

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

        doAnswer(invocation -> {
            ActionListener<String> listener = invocation.getArgument(1);
            listener.onResponse("test-doc-id");
            return null;
        }).when(apiTokenIndexHandler).indexTokenMetadata(any(ApiToken.class), any(ActionListener.class));

        doAnswer(invocation -> {
            ActionListener<?> l = invocation.getArgument(0);
            l.onResponse(null);
            return null;
        }).when(apiTokenIndexHandler).createApiTokenIndexIfAbsent(any(ActionListener.class));

        TestActionListener<ApiTokenRepository.TokenCreated> listener = new TestActionListener<>();
        repository.createApiToken(tokenName, clusterPermissions, indexPermissions, expiration, listener);
        ApiTokenRepository.TokenCreated created = listener.assertSuccess();

        assertTrue("Token should start with os_ prefix", created.token().startsWith(ApiTokenRepository.TOKEN_PREFIX));
        assertThat(created.id(), equalTo("test-doc-id"));
        verify(apiTokenIndexHandler).createApiTokenIndexIfAbsent(any());
        verify(apiTokenIndexHandler).indexTokenMetadata(
            argThat(
                token -> token.getName().equals(tokenName)
                    && token.getClusterPermissions().equals(clusterPermissions)
                    && token.getIndexPermissions().equals(indexPermissions)
                    && token.getExpiration().equals(expiration)
                    && token.getTokenHash().equals(ApiTokenRepository.hashToken(created.token()))
            ),
            any(ActionListener.class)
        );
    }

    @Test
    public void testRevokeApiTokenThrowsApiTokenException() {
        String tokenName = "test-token";

        doAnswer(invocation -> {
            ActionListener<Void> listener = invocation.getArgument(1);
            listener.onFailure(new ApiTokenException("Token not found"));
            return null;
        }).when(apiTokenIndexHandler).revokeToken(eq(tokenName), any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.revokeApiToken(tokenName, listener);

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
    public void testReloadApiTokensFromIndexWithMultipleTokens() {
        Map<String, ApiToken> tokens = Map.of(
            HASH_ALPHA,
            new ApiToken("alpha", HASH_ALPHA, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE),
            HASH_BETA,
            new ApiToken(
                "beta",
                HASH_BETA,
                List.of("cluster:admin"),
                List.of(new ApiToken.IndexPermission(List.of("logs-*"), List.of("read"))),
                Instant.now(),
                Long.MAX_VALUE
            )
        );

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(tokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.reloadApiTokensFromIndex(listener);

        listener.assertSuccess();
        assertEquals(2, repository.getJtis().size());
        assertTrue(repository.getJtis().containsKey(HASH_ALPHA));
        assertTrue(repository.getJtis().containsKey(HASH_BETA));
        assertEquals(List.of("cluster:monitor"), repository.getJtis().get(HASH_ALPHA).getCluster_permissions());
        assertEquals(List.of("cluster:admin"), repository.getJtis().get(HASH_BETA).getCluster_permissions());
        assertEquals(1, repository.getJtis().get(HASH_BETA).getIndex_permissions().size());
    }

    @Test
    public void testReloadApiTokensFromIndexExcludesRevokedTokens() {
        Map<String, ApiToken> tokens = Map.of(
            HASH_ALPHA,
            new ApiToken("active", HASH_ALPHA, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE, null),
            HASH_BETA,
            new ApiToken("revoked", HASH_BETA, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE, Instant.now())
        );

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(tokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.reloadApiTokensFromIndex(listener);

        listener.assertSuccess();
        assertTrue("Active token should be in cache", repository.getJtis().containsKey(HASH_ALPHA));
        assertFalse("Revoked token should not be in cache", repository.getJtis().containsKey(HASH_BETA));
    }

    @Test
    public void testReloadApiTokensFromIndexEvictsTokenThatBecomesRevoked() {
        // Seed the cache with a token that is about to be revoked
        RoleV7 role = new RoleV7();
        role.setCluster_permissions(List.of("cluster:monitor"));
        repository.getJtis().put(HASH_BETA, role);

        // Next reload returns the same token but now with revoked_at set
        Map<String, ApiToken> tokens = Map.of(
            HASH_BETA,
            new ApiToken("revoked", HASH_BETA, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE, Instant.now())
        );

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(tokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.reloadApiTokensFromIndex(listener);

        listener.assertSuccess();
        assertFalse("Token should be evicted from cache after revocation", repository.getJtis().containsKey(HASH_BETA));
        assertFalse("Token should be evicted from expiration cache after revocation", repository.isValidToken(HASH_BETA));
    }

    @Test
    public void testReloadApiTokensFromIndexRemovesStaleTokens() {
        RoleV7 staleRole = new RoleV7();
        staleRole.setCluster_permissions(List.of("cluster:monitor"));
        repository.getJtis().put(HASH_STALE, staleRole);

        Map<String, ApiToken> freshTokens = Map.of(
            HASH_FRESH,
            new ApiToken("fresh", HASH_FRESH, List.of("cluster:admin"), List.of(), Instant.now(), Long.MAX_VALUE)
        );

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(freshTokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        TestActionListener<Void> listener = new TestActionListener<>();
        repository.reloadApiTokensFromIndex(listener);

        listener.assertSuccess();
        assertFalse("Stale token should be removed", repository.getJtis().containsKey(HASH_STALE));
        assertTrue("Fresh token should be present", repository.getJtis().containsKey(HASH_FRESH));
    }

    @Test
    public void testReloadApiTokensFromIndexOnlyCallsListenerOnce() {
        Map<String, ApiToken> tokens = Map.of(
            HASH_ONE,
            new ApiToken("one", HASH_ONE, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE),
            HASH_TWO,
            new ApiToken("two", HASH_TWO, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE),
            HASH_THREE,
            new ApiToken("three", HASH_THREE, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE)
        );

        doAnswer(invocation -> {
            ActionListener<Map<String, ApiToken>> listener = invocation.getArgument(0);
            listener.onResponse(tokens);
            return null;
        }).when(apiTokenIndexHandler).getTokenMetadatas(any(ActionListener.class));

        // Use a counter to verify listener is called exactly once
        int[] callCount = { 0 };
        repository.reloadApiTokensFromIndex(ActionListener.wrap(unused -> callCount[0]++, e -> {}));

        assertEquals("Listener should be called exactly once regardless of token count", 1, callCount[0]);
    }

    @Test
    public void testReloadApiTokensFromIndexAndParse() throws IOException {
        // Setup mock response
        Map<String, ApiToken> expectedTokens = Map.of(
            "test",
            new ApiToken("test", HASH_TEST, List.of("cluster:monitor"), List.of(), Instant.now(), Long.MAX_VALUE)
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
