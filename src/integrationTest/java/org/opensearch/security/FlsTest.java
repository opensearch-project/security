/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.metrics.ParsedAvg;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.FIELD_ARTIST;
import static org.opensearch.security.Song.FIELD_LYRICS;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.opensearch.security.Song.FIELD_TITLE;
import static org.opensearch.security.Song.QUERY_TITLE_MAGNUM_OPUS;
import static org.opensearch.security.Song.QUERY_TITLE_NEXT_SONG;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsExactlyIndices;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsFieldWithNameAndType;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.numberOfFieldsIsEqualTo;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containDocument;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentContainsExactlyFieldsWithNames;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.isSuccessfulMultiGetResponse;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.numberOfGetItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.isSuccessfulMultiSearchResponse;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.numberOfSearchItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsDocumentsContainExactlyFieldsWithNames;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FlsTest {

    static final String ID_SONG_1 = "S1";
    static final String ID_SONG_2 = "S2";
    static final String ID_SONG_3 = "S3";
    static final String ID_SONG_4 = "S4";

    static final String FLS_INDEX_NAME_SUFFIX = "-fls-test-index";
    static final String FIRST_FLS_INDEX_NAME = "first".concat(FLS_INDEX_NAME_SUFFIX);
    static final String SECOND_FLS_INDEX_NAME = "second".concat(FLS_INDEX_NAME_SUFFIX);
    static final String FIRST_FLS_INDEX_ALIAS = FIRST_FLS_INDEX_NAME.concat("-alias");
    static final String SECOND_FLS_INDEX_ALIAS = SECOND_FLS_INDEX_NAME.concat("-alias");
    static final String FIRST_FLS_INDEX_FILTERED_ALIAS = FIRST_FLS_INDEX_NAME.concat("-filtered-alias");


    /**
     * User who is allowed to see the title and stars fields on all indices
     */
    static final TestSecurityConfig.User ALL_INDICES_TITLE_STARS_READER = new TestSecurityConfig.User("title_stars_reader")
            .roles(
                    new TestSecurityConfig.Role("title_stars_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(FIELD_TITLE, FIELD_STARS)
                            .on("*")
            );

    /**
     * User who is allowed to see the title, artist and lyrics fields on index {@link #FIRST_FLS_INDEX_NAME}, and
     * the artist field on index {@link #SECOND_FLS_INDEX_NAME}
     */
    static final TestSecurityConfig.User TITLE_ARTIST_LYRICS_READER_USER = new TestSecurityConfig.User("title_artist_lyrics_reader")
            .roles(
                    new TestSecurityConfig.Role("title_artist_lyrics_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(
                                    FIELD_TITLE,
                                    FIELD_ARTIST.substring(0,3).concat("*"),
                                    "*".concat(FIELD_LYRICS.substring(FIELD_LYRICS.length() - 3))
                            )
                            .on(FIRST_FLS_INDEX_NAME),
                    new TestSecurityConfig.Role("artist_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(FIELD_ARTIST)
                            .on(SECOND_FLS_INDEX_NAME)
            );

    /**
     * User who is allowed to see the title field on index {@link #FIRST_FLS_INDEX_NAME}
     */
    static final TestSecurityConfig.User TITLE_READER = new TestSecurityConfig.User("title_reader")
            .roles(
                    new TestSecurityConfig.Role("title_reader")
                            .clusterPermissions("cluster_composite_ops_ro")
                            .indexPermissions("read")
                            .fls(
                                    "~".concat(FIELD_ARTIST),
                                    "~".concat(FIELD_LYRICS.substring(0,3).concat("*")),
                                    "~*".concat(FIELD_STARS.substring(FIELD_STARS.length() - 3))
                            )
                            .on(FIRST_FLS_INDEX_NAME)
            );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder()
            .clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS).anonymousAuth(false)
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(ALL_INDICES_TITLE_STARS_READER, TITLE_ARTIST_LYRICS_READER_USER, TITLE_READER)
            .build();

    @BeforeClass
    public static void createTestData() {
        try(Client client = cluster.getInternalNodeClient()){
            client.prepareIndex(FIRST_FLS_INDEX_NAME).setId(ID_SONG_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0]).get();
            client.prepareIndex(FIRST_FLS_INDEX_NAME).setId(ID_SONG_2).setRefreshPolicy(IMMEDIATE).setSource(SONGS[1]).get();
            client.prepareIndex(FIRST_FLS_INDEX_NAME).setId(ID_SONG_3).setRefreshPolicy(IMMEDIATE).setSource(SONGS[2]).get();
            client.prepareIndex(FIRST_FLS_INDEX_NAME).setId(ID_SONG_4).setRefreshPolicy(IMMEDIATE).setSource(SONGS[3]).get();
            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .indices(FIRST_FLS_INDEX_NAME)
                    .alias(FIRST_FLS_INDEX_ALIAS)
            )).actionGet();
            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .index(FIRST_FLS_INDEX_NAME)
                    .alias(FIRST_FLS_INDEX_FILTERED_ALIAS)
                    .filter(QueryBuilders.queryStringQuery(QUERY_TITLE_NEXT_SONG))
            )).actionGet();

            client.prepareIndex(SECOND_FLS_INDEX_NAME).setId(ID_SONG_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0]).get();
            client.prepareIndex(SECOND_FLS_INDEX_NAME).setId(ID_SONG_2).setRefreshPolicy(IMMEDIATE).setSource(SONGS[1]).get();
            client.prepareIndex(SECOND_FLS_INDEX_NAME).setId(ID_SONG_3).setRefreshPolicy(IMMEDIATE).setSource(SONGS[2]).get();
            client.prepareIndex(SECOND_FLS_INDEX_NAME).setId(ID_SONG_4).setRefreshPolicy(IMMEDIATE).setSource(SONGS[3]).get();
            client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
                    .indices(SECOND_FLS_INDEX_NAME)
                    .alias(SECOND_FLS_INDEX_ALIAS)
            )).actionGet();
        }
    }

    @Test
    public void searchForDocuments() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_FLS_INDEX_NAME);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_FLS_INDEX_NAME);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE));
        }
    }

    @Test
    public void searchForDocumentsWithIndexPattern() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest("*".concat(FLS_INDEX_NAME_SUFFIX));

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_FLS_INDEX_NAME, FIELD_ARTIST));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest("*".concat(FIRST_FLS_INDEX_NAME));

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE));
        }
    }

    @Test
    public void searchForDocumentsViaAlias() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_FLS_INDEX_ALIAS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));

            searchRequest = new SearchRequest(SECOND_FLS_INDEX_ALIAS);

            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_FLS_INDEX_NAME, FIELD_ARTIST));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_FLS_INDEX_ALIAS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE));
        }
    }

    @Test
    public void searchForDocumentsViaFilteredAlias() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_FLS_INDEX_FILTERED_ALIAS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_FLS_INDEX_FILTERED_ALIAS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE));
        }
    }

    @Test
    public void searchForDocumentsViaAllIndicesAlias() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_TITLE_STARS_READER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_FLS_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
        }
    }

    @Test
    public void scrollOverSearchResults() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(FIRST_FLS_INDEX_NAME, 2);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            SearchRequest searchRequest = searchRequestWithScroll(FIRST_FLS_INDEX_NAME, 2);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(searchResponse, searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE));
        }
    }

    @Test
    public void aggregateDataAndComputeAverage() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_TITLE_STARS_READER)) {
            final String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_FLS_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), not(Double.POSITIVE_INFINITY));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            final String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_FLS_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(Double.POSITIVE_INFINITY));
        }
    }
    @Test
    public void getDocument() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_FLS_INDEX_NAME, ID_SONG_1), DEFAULT);

            assertThat(response, containDocument(FIRST_FLS_INDEX_NAME, ID_SONG_1));
            assertThat(response, documentContainsExactlyFieldsWithNames(FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS));
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_FLS_INDEX_NAME, ID_SONG_1), DEFAULT);

            assertThat(response, containDocument(FIRST_FLS_INDEX_NAME, ID_SONG_1));
            assertThat(response, documentContainsExactlyFieldsWithNames(FIELD_TITLE));
        }
    }

    @Test
    public void multiGetDocuments() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            MultiGetRequest request = new MultiGetRequest();
            request.add(new MultiGetRequest.Item(FIRST_FLS_INDEX_NAME, ID_SONG_1));
            request.add(new MultiGetRequest.Item(FIRST_FLS_INDEX_NAME, ID_SONG_2));

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses[0].getResponse(), allOf(
                    containDocument(FIRST_FLS_INDEX_NAME, ID_SONG_1),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS))
            );
            assertThat(responses[1].getResponse(),  allOf(
                    containDocument(FIRST_FLS_INDEX_NAME, ID_SONG_2),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE, FIELD_ARTIST, FIELD_LYRICS))
            );
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            MultiGetRequest request = new MultiGetRequest();
            request.add(new MultiGetRequest.Item(FIRST_FLS_INDEX_NAME, ID_SONG_3));
            request.add(new MultiGetRequest.Item(FIRST_FLS_INDEX_NAME, ID_SONG_4));

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses[0].getResponse(), allOf(
                    containDocument(FIRST_FLS_INDEX_NAME, ID_SONG_3),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE))
            );
            assertThat(responses[1].getResponse(),  allOf(
                    containDocument(FIRST_FLS_INDEX_NAME, ID_SONG_4),
                    documentContainsExactlyFieldsWithNames(FIELD_TITLE))
            );
        }
    }

    @Test
    public void multiSearchDocuments() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_TITLE_STARS_READER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(FIRST_FLS_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(SECOND_FLS_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();

            assertThat(responses[0].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
            assertThat(responses[1].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(SECOND_FLS_INDEX_NAME, FIELD_TITLE, FIELD_STARS));
        }


        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(FIRST_FLS_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(FIRST_FLS_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();

            assertThat(responses[0].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE));
            assertThat(responses[1].getResponse(), searchHitsDocumentsContainExactlyFieldsWithNames(FIRST_FLS_INDEX_NAME, FIELD_TITLE));
        }
    }

    @Test
    public void getFieldCapabilities() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_ARTIST_LYRICS_READER_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(FIRST_FLS_INDEX_NAME).fields(FIELD_STARS);

            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, containsExactlyIndices(FIRST_FLS_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(0));
        }
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(TITLE_READER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(FIRST_FLS_INDEX_NAME).fields(FIELD_TITLE, FIELD_ARTIST, FIELD_STARS);

            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, containsExactlyIndices(FIRST_FLS_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(1));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
        }
    }

}
