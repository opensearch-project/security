/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.action.apitokens;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

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
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.security.support.ConfigConstants;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ApiTokenIndexListenerCacheTest {

    private ApiTokenIndexListenerCache cache;

    @Mock
    private ClusterService clusterService;

    @Mock
    private Client client;

    @Mock
    private ClusterChangedEvent event;

    @Mock
    private ClusterState clusterState;

    @Mock
    private IndexMetadata indexMetadata;
    @Mock
    private SearchResponse searchResponse;

    @Mock
    private SearchRequestBuilder searchRequestBuilder;

    @Mock
    private ActionFuture<SearchResponse> actionFuture;

    @Before
    public void setUp() {
        ApiTokenIndexListenerCache.getInstance().initialize(clusterService, client);
        cache = ApiTokenIndexListenerCache.getInstance();
    }

    @Test
    public void testSingleton() {
        ApiTokenIndexListenerCache instance1 = ApiTokenIndexListenerCache.getInstance();
        ApiTokenIndexListenerCache instance2 = ApiTokenIndexListenerCache.getInstance();
        assertSame("getInstance should always return the same instance", instance1, instance2);
    }

    @Test
    public void testJtisOperations() {
        String jti = "testJti";
        Permissions permissions = new Permissions(List.of("read"), List.of(new ApiToken.IndexPermission(List.of(), List.of())));

        cache.getJtis().put(jti, permissions);
        assertEquals("Should retrieve correct permissions", permissions, cache.getJtis().get(jti));

        cache.getJtis().remove(jti);
        assertNull("Should return null after removal", cache.getJtis().get(jti));
    }

    @Test
    public void testClearJtis() {
        cache.getJtis().put("testJti", new Permissions(List.of("read"), List.of(new ApiToken.IndexPermission(List.of(), List.of()))));
        cache.reloadApiTokensFromIndex();

        assertTrue("Jtis should be empty after clear", cache.getJtis().isEmpty());
    }

    @Test
    public void testClusterChangedInvokesReloadTokens() {
        ClusterState clusterState = mock(ClusterState.class);
        Metadata metadata = mock(Metadata.class);
        when(clusterState.metadata()).thenReturn(metadata);
        when(metadata.index(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(indexMetadata);
        when(event.state()).thenReturn(clusterState);

        ApiTokenIndexListenerCache cacheSpy = spy(cache);
        cacheSpy.clusterChanged(event);

        verify(cacheSpy).reloadApiTokensFromIndex();
    }

    @Test
    public void testReloadApiTokensFromIndexAndParse() throws IOException {
        SearchHit hit = createSearchHitFromApiToken("1", "testJti", Arrays.asList("cluster:monitor"), List.of());

        SearchHits searchHits = new SearchHits(new SearchHit[] { hit }, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1.0f);

        // Mock the search response
        when(searchResponse.getHits()).thenReturn(searchHits);
        when(client.prepareSearch(any())).thenReturn(searchRequestBuilder);
        when(searchRequestBuilder.setQuery(any())).thenReturn(searchRequestBuilder);
        when(searchRequestBuilder.execute()).thenReturn(actionFuture);
        when(actionFuture.actionGet()).thenReturn(searchResponse);

        // Execute the reload
        cache.reloadApiTokensFromIndex();

        // Verify the cache was updated
        assertFalse("Jtis should not be empty after reload", cache.getJtis().isEmpty());
        assertEquals("Should have one JTI entry", 1, cache.getJtis().size());
        assertTrue("Should contain testJti", cache.getJtis().containsKey("testJti"));
        // Verify extraction works
        assertEquals("Should have one cluster action", List.of("cluster:monitor"), cache.getJtis().get("testJti").getClusterPerm());
        assertEquals("Should have no index actions", List.of(), cache.getJtis().get("testJti").getIndexPermission());
    }

    private SearchHit createSearchHitFromApiToken(
        String id,
        String jti,
        List<String> allowedActions,
        List<ApiToken.IndexPermission> prohibitedActions
    ) throws IOException {
        ApiToken apiToken = new ApiToken("test", jti, allowedActions, prohibitedActions, Long.MAX_VALUE);
        XContentBuilder builder = XContentFactory.jsonBuilder();
        apiToken.toXContent(builder, null);

        SearchHit hit = new SearchHit(Integer.parseInt(id), id, null, null, null);
        hit.sourceRef(BytesReference.bytes(builder));
        return hit;
    }

}
