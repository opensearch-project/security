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

import org.apache.lucene.search.TotalHits;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.search.SearchRequestBuilder;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.security.authtoken.jwt.ExpiringBearerAuthToken;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.support.ConfigConstants;

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
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ApiTokenRepositoryTest {
    @Mock
    private SecurityTokenManager securityTokenManager;

    @Mock
    private ApiTokenIndexHandler apiTokenIndexHandler;
    @Mock
    private IndexMetadata indexMetadata;
    @Mock
    private SearchResponse searchResponse;

    @Mock
    private SearchRequestBuilder searchRequestBuilder;

    @Mock
    private ActionFuture<SearchResponse> actionFuture;
    @Mock
    private Client client;
    @Mock
    private ClusterChangedEvent event;

    private ApiTokenRepository repository;

    @Before
    public void setUp() {
        apiTokenIndexHandler = mock(ApiTokenIndexHandler.class);
        securityTokenManager = mock(SecurityTokenManager.class);
        repository = ApiTokenRepository.forTest(apiTokenIndexHandler, securityTokenManager, client);
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
    public void testClusterChangedInvokesReloadTokens() {
        ClusterState clusterState = mock(ClusterState.class);
        Metadata metadata = mock(Metadata.class);
        when(clusterState.metadata()).thenReturn(metadata);
        when(metadata.index(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(indexMetadata);
        when(event.state()).thenReturn(clusterState);

        ApiTokenRepository cacheSpy = spy(repository);
        cacheSpy.clusterChanged(event);

        verify(cacheSpy).reloadApiTokensFromIndex();
    }

    @Test
    public void testReloadApiTokensFromIndexAndParse() throws IOException {
        SearchHit hit = createSearchHitFromApiToken("1", Arrays.asList("cluster:monitor"), List.of());

        SearchHits searchHits = new SearchHits(new SearchHit[] { hit }, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        // Mock the search response
        when(searchResponse.getHits()).thenReturn(searchHits);
        when(client.prepareSearch(any())).thenReturn(searchRequestBuilder);
        when(searchRequestBuilder.setQuery(any())).thenReturn(searchRequestBuilder);
        when(searchRequestBuilder.execute()).thenReturn(actionFuture);
        when(actionFuture.actionGet()).thenReturn(searchResponse);

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

    private SearchHit createSearchHitFromApiToken(String id, List<String> allowedActions, List<ApiToken.IndexPermission> prohibitedActions)
        throws IOException {
        ApiToken apiToken = new ApiToken("test", allowedActions, prohibitedActions, Long.MAX_VALUE);
        XContentBuilder builder = XContentFactory.jsonBuilder();
        apiToken.toXContent(builder, null);

        SearchHit hit = new SearchHit(Integer.parseInt(id), id, null, null, null);
        hit.sourceRef(BytesReference.bytes(builder));
        return hit;
    }
}
