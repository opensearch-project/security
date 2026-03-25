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

import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.util.ActionListenerUtils.TestActionListener;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked")
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

        indexHandler.createApiTokenIndexIfAbsent(ActionListener.wrap(() -> {
            ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
            verify(indicesAdminClient).create(captor.capture());
            assertThat(captor.getValue().index(), equalTo(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX));
        }));
    }

    @Test
    public void testCreateApiTokenIndexWhenIndexExists() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        indexHandler.createApiTokenIndexIfAbsent(ActionListener.wrap(() -> {
            verifyNoInteractions(indicesAdminClient);
        }));
    }

    @Test
    public void testRevokeApiTokenCallsUpdateWithSuppliedId() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);
        String tokenId = "doc-id-123";

        TestActionListener<Void> listener = new TestActionListener<>();

        doAnswer(invocation -> {
            ActionListener<UpdateResponse> parentListener = invocation.getArgument(1);
            UpdateResponse response = mock(UpdateResponse.class);
            when(response.getResult()).thenReturn(DocWriteResponse.Result.UPDATED);
            parentListener.onResponse(response);
            return null;
        }).when(client).update(any(UpdateRequest.class), any(ActionListener.class));

        indexHandler.revokeToken(tokenId, listener);

        ArgumentCaptor<UpdateRequest> captor = ArgumentCaptor.forClass(UpdateRequest.class);
        verify(client).update(captor.capture(), any(ActionListener.class));
        listener.assertSuccess();

        UpdateRequest capturedRequest = captor.getValue();
        assertThat(capturedRequest.index(), equalTo(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX));
        assertThat(capturedRequest.id(), equalTo(tokenId));
    }

    @Test
    public void testRevokeTokenThrowsExceptionWhenTokenNotFound() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        doAnswer(invocation -> {
            ActionListener<UpdateResponse> listener = invocation.getArgument(1);
            UpdateResponse response = mock(UpdateResponse.class);
            when(response.getResult()).thenReturn(DocWriteResponse.Result.NOT_FOUND);
            listener.onResponse(response);
            return null;
        }).when(client).update(any(UpdateRequest.class), any(ActionListener.class));

        String tokenId = "nonexistent-id";
        TestActionListener<Void> listener = new TestActionListener<>();
        indexHandler.revokeToken(tokenId, listener);

        Exception e = listener.assertException(ApiTokenException.class);
        assertThat(e.getMessage(), containsString("No token found with id " + tokenId));
    }

    @Test
    public void testRevokeTokenSucceedsWhenDocumentIsUpdated() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        doAnswer(invocation -> {
            ActionListener<UpdateResponse> listener = invocation.getArgument(1);
            UpdateResponse response = mock(UpdateResponse.class);
            when(response.getResult()).thenReturn(DocWriteResponse.Result.UPDATED);
            listener.onResponse(response);
            return null;
        }).when(client).update(any(UpdateRequest.class), any(ActionListener.class));

        String tokenId = "existing-id";
        TestActionListener<Void> listener = new TestActionListener<>();
        indexHandler.revokeToken(tokenId, listener);

        listener.assertSuccess();
    }

    @Test
    public void testIndexTokenStoresTokenPayload() {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        List<String> clusterPermissions = Arrays.asList("cluster:admin/something");
        List<ApiToken.IndexPermission> indexPermissions = Arrays.asList(
                new ApiToken.IndexPermission(
                        Arrays.asList("test-index-*"),
                        Arrays.asList("read", "write")
                )
        );
        ApiToken token = new ApiToken(
                "test-token-description",
                ApiTokenRepository.hashToken("os_test"),
                clusterPermissions,
                indexPermissions,
                Instant.now(),
                Long.MAX_VALUE
        );

        // Mock the index response
        doAnswer(invocation -> {
            ActionListener<IndexResponse> listener = invocation.getArgument(1);
            IndexResponse mockResponse = mock(IndexResponse.class);
            when(mockResponse.getId()).thenReturn("test-doc-id");
            listener.onResponse(mockResponse);
            return null;
        }).when(client).index(any(IndexRequest.class), any(ActionListener.class));

        TestActionListener<String> listener = new TestActionListener<>();
        indexHandler.indexTokenMetadata(token, listener);

        String id = listener.assertSuccess();
        assertThat(id, equalTo("test-doc-id"));

        ArgumentCaptor<IndexRequest> requestCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(client).index(requestCaptor.capture(), any(ActionListener.class));

        IndexRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.index(), equalTo(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX));

        String source = capturedRequest.source().utf8ToString();
        assertThat(source, containsString("test-token-description"));
        assertThat(source, containsString("cluster:admin/something"));
        assertThat(source, containsString("test-index-*"));
    }

    @Test
    public void testGetTokenPayloads() throws IOException {
        when(metadata.hasConcreteIndex(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX)).thenReturn(true);

        // Create sample search hits
        SearchHit[] hits = new SearchHit[2];

        // First token
        ApiToken token1 = new ApiToken(
                "token1-description",
                ApiTokenRepository.hashToken("os_token1"),
                Arrays.asList("cluster:admin/something"),
                Arrays.asList(new ApiToken.IndexPermission(
                        Arrays.asList("index1-*"),
                        Arrays.asList("read")
                )),
                Instant.now(),
                Long.MAX_VALUE
        );

        // Second token
        ApiToken token2 = new ApiToken(
                "token2-description",
                ApiTokenRepository.hashToken("os_token2"),
                Arrays.asList("cluster:admin/other"),
                Arrays.asList(new ApiToken.IndexPermission(
                        Arrays.asList("index2-*"),
                        Arrays.asList("write")
                )),
                Instant.now(),
                Long.MAX_VALUE
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

        doAnswer(invocation -> {
            ActionListener<SearchResponse> listener = invocation.getArgument(1);
            listener.onResponse(searchResponse);
            return null;
        }).when(client).search(any(SearchRequest.class), any(ActionListener.class));

        TestActionListener<Map<String, ApiToken>> listener = new TestActionListener<>();
        indexHandler.getTokenMetadatas(listener);

        Map<String, ApiToken> resultTokens = listener.assertSuccess();
        assertThat(resultTokens.size(), equalTo(2));
        assertThat(resultTokens.containsKey(ApiTokenRepository.hashToken("os_token1")), is(true));
        assertThat(resultTokens.containsKey(ApiTokenRepository.hashToken("os_token2")), is(true));

        ApiToken resultToken1 = resultTokens.get(ApiTokenRepository.hashToken("os_token1"));
        assertThat(resultToken1.getClusterPermissions(), contains("cluster:admin/something"));

        ApiToken resultToken2 = resultTokens.get(ApiTokenRepository.hashToken("os_token2"));
        assertThat(resultToken2.getClusterPermissions(), contains("cluster:admin/other"));
    }
}
