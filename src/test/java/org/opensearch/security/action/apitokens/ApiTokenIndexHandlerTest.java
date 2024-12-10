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
import java.util.List;
import java.util.Map;

import org.apache.lucene.search.TotalHits;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class ApiTokenIndexHandlerTest {

    @Mock
    private Client client;

    @Mock
    private IndicesAdminClient indicesAdminClient;

    @Mock
    private ClusterService clusterService;

    @Mock
    private Metadata metadata;

    private ApiTokenIndexHandler indexHandler;

    @Before
    public void setup() {

        client = mock(Client.class, RETURNS_DEEP_STUBS);
        indicesAdminClient = mock(IndicesAdminClient.class);
        clusterService = mock(ClusterService.class, RETURNS_DEEP_STUBS);
        metadata = mock(Metadata.class);

        when(client.admin().indices()).thenReturn(indicesAdminClient);

        when(clusterService.state().metadata()).thenReturn(metadata);

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        when(client.threadPool().getThreadContext()).thenReturn(threadContext);

        indexHandler = new ApiTokenIndexHandler(client, clusterService);
    }

    @Test
    public void testCreateApiTokenIndexWhenIndexNotExist() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(false);

        indexHandler.createApiTokenIndexIfAbsent();

        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);

        verify(indicesAdminClient).create(captor.capture());
        assertThat(captor.getValue().index(), equalTo(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX));
    }

    @Test
    public void testCreateApiTokenIndexWhenIndexExists() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        indexHandler.createApiTokenIndexIfAbsent();

        verifyNoInteractions(indicesAdminClient);
    }

    @Test
    public void testDeleteApiTokeCallsDeleteByQueryWithSuppliedName() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);
        String tokenName = "token";
        try {
            indexHandler.deleteToken(tokenName);
        } catch (Exception e) {
            // Ignore
        }

        ArgumentCaptor<DeleteByQueryRequest> captor = ArgumentCaptor.forClass(DeleteByQueryRequest.class);
        verify(client).execute(eq(DeleteByQueryAction.INSTANCE), captor.capture());

        // Verify the captured request has the correct query parameters
        DeleteByQueryRequest capturedRequest = captor.getValue();
        MatchQueryBuilder query = (MatchQueryBuilder) capturedRequest.getSearchRequest().source().query();
        assertThat(query.fieldName(), equalTo("description"));
        assertThat(query.value(), equalTo(tokenName));
    }

    @Test
    public void testDeleteTokenThrowsExceptionWhenNoDocumentsDeleted() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        PlainActionFuture<BulkByScrollResponse> future = new PlainActionFuture<>();
        BulkByScrollResponse response = mock(BulkByScrollResponse.class);
        when(response.getDeleted()).thenReturn(0L);
        future.onResponse(response);
        when(client.execute(eq(DeleteByQueryAction.INSTANCE), any(DeleteByQueryRequest.class))).thenReturn(future);

        String tokenName = "nonexistent-token";
        try {
            indexHandler.deleteToken(tokenName);
            fail("Expected ApiTokenException to be thrown");
        } catch (ApiTokenException e) {
            assertThat(e.getMessage(), equalTo("No token found with name " + tokenName));
        }
    }

    @Test
    public void testDeleteTokenSucceedsWhenDocumentIsDeleted() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        // Mock response with 1 deleted document
        PlainActionFuture<BulkByScrollResponse> future = new PlainActionFuture<>();
        BulkByScrollResponse response = mock(BulkByScrollResponse.class);
        when(response.getDeleted()).thenReturn(1L);
        future.onResponse(response);
        when(client.execute(eq(DeleteByQueryAction.INSTANCE), any(DeleteByQueryRequest.class))).thenReturn(future);

        String tokenName = "existing-token";
        try {
            indexHandler.deleteToken(tokenName);
        } catch (ApiTokenException e) {
            fail("Should not have thrown exception");
        }
    }

    @Test
    public void testIndexTokenStoresToken() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        // Create a real ApiToken
        List<String> clusterPermissions = Arrays.asList("cluster:admin/something");
        List<RoleV7.Index> indexPermissions = Arrays.asList(
                new RoleV7.Index(
                        Arrays.asList("test-index-*"),
                        Arrays.asList("read", "write"),
                        null,  // dls
                        null,  // fls
                        null   // masked_fields
                )
        );
        ApiToken token = new ApiToken(
                "test-token-description",
                "test-jti",
                clusterPermissions,
                indexPermissions,
                Instant.now()
        );

        // Mock the index method with ActionListener
        @SuppressWarnings("unchecked")
        ArgumentCaptor<ActionListener<IndexResponse>> listenerCaptor =
                ArgumentCaptor.forClass((Class<ActionListener<IndexResponse>>) (Class<?>) ActionListener.class);

        doAnswer(invocation -> {
            ActionListener<IndexResponse> listener = listenerCaptor.getValue();
            listener.onResponse(new IndexResponse(
                    new ShardId(".opensearch_security_api_tokens", "_na_", 1),
                    "1",
                    0,
                    1,
                    1,
                    true
            ));
            return null;
        }).when(client).index(any(IndexRequest.class), listenerCaptor.capture());

        indexHandler.indexToken(token);

        // Verify the index request
        ArgumentCaptor<IndexRequest> requestCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(client).index(requestCaptor.capture(), listenerCaptor.capture());

        IndexRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.index(), equalTo(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX));

        // Convert the source to a string and verify contents
        String source = capturedRequest.source().utf8ToString();
        assertThat(source, containsString("test-token-description"));
        assertThat(source, containsString("test-jti"));
        assertThat(source, containsString("cluster:admin/something"));
        assertThat(source, containsString("test-index-*"));
    }

    @Test
    public void testGetApiTokens() throws IOException {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        // Create sample search hits
        SearchHit[] hits = new SearchHit[2];

        // First token
        ApiToken token1 = new ApiToken(
                "token1-description",
                "jti1",
                Arrays.asList("cluster:admin/something"),
                Arrays.asList(new RoleV7.Index(
                        Arrays.asList("index1-*"),
                        Arrays.asList("read"),
                        null, null, null
                )),
                Instant.now()
        );

        // Second token
        ApiToken token2 = new ApiToken(
                "token2-description",
                "jti2",
                Arrays.asList("cluster:admin/other"),
                Arrays.asList(new RoleV7.Index(
                        Arrays.asList("index2-*"),
                        Arrays.asList("write"),
                        null, null, null
                )),
                Instant.now()
        );

        // Convert tokens to XContent and create SearchHits
        XContentBuilder builder1 = XContentBuilder.builder(XContentType.JSON.xContent());
        token1.toXContent(builder1, ToXContent.EMPTY_PARAMS);
        hits[0] = new SearchHit(1, "1", null, null);
        hits[0].sourceRef(BytesReference.bytes(builder1));

        XContentBuilder builder2 = XContentBuilder.builder(XContentType.JSON.xContent());
        token2.toXContent(builder2, ToXContent.EMPTY_PARAMS);
        hits[1] = new SearchHit(2, "2", null, null);
        hits[1].sourceRef(BytesReference.bytes(builder2));

        // Create and mock search response
        SearchResponse searchResponse = mock(SearchResponse.class);
        SearchHits searchHits = new SearchHits(hits, new TotalHits(2, TotalHits.Relation.EQUAL_TO), 1.0f);
        when(searchResponse.getHits()).thenReturn(searchHits);

        // Mock client search call
        PlainActionFuture<SearchResponse> future = new PlainActionFuture<>();
        future.onResponse(searchResponse);
        when(client.search(any(SearchRequest.class))).thenReturn(future);

        // Get tokens and verify
        Map<String, ApiToken> resultTokens = indexHandler.getApiTokens();

        assertThat(resultTokens.size(), equalTo(2));
        assertThat(resultTokens.containsKey("token1-description"), is(true));
        assertThat(resultTokens.containsKey("token2-description"), is(true));

        ApiToken resultToken1 = resultTokens.get("token1-description");
        assertThat(resultToken1.getJti(), equalTo("jti1"));
        assertThat(resultToken1.getClusterPermissions(), contains("cluster:admin/something"));

        ApiToken resultToken2 = resultTokens.get("token2-description");
        assertThat(resultToken2.getJti(), equalTo("jti2"));
        assertThat(resultToken2.getClusterPermissions(), contains("cluster:admin/other"));
    }

}
