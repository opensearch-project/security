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

import java.io.IOException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.hamcrest.Matchers;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.opensearch.security.Song.FIELD_TITLE;
import static org.opensearch.security.Song.QUERY_TITLE_MAGNUM_OPUS;
import static org.opensearch.security.Song.QUERY_TITLE_NEXT_SONG;
import static org.opensearch.security.Song.QUERY_TITLE_POISON;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.Song.TITLE_MAGNUM_OPUS;
import static org.opensearch.security.Song.TITLE_NEXT_SONG;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.statsAggregationRequest;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containDocument;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containOnlyDocumentId;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfHitsInPageIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentWithId;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DoNotFailOnForbiddenTests {

    /**
    * Songs accessible for {@link #LIMITED_USER}
    */
    private static final String MARVELOUS_SONGS = "marvelous_songs";

    /**
    * Songs inaccessible for {@link #LIMITED_USER}
    */
    private static final String HORRIBLE_SONGS = "horrible_songs";

    private static final String BOTH_INDEX_PATTERN = "*songs";

    private static final String ID_1 = "1";
    private static final String ID_2 = "2";
    private static final String ID_3 = "3";
    private static final String ID_4 = "4";

    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);
    private static final User LIMITED_USER = new User("limited_user").roles(
        new TestSecurityConfig.Role("limited-role").clusterPermissions(
            "indices:data/read/mget",
            "indices:data/read/msearch",
            "indices:data/read/scroll"
        )
            .indexPermissions(
                "indices:data/read/search",
                "indices:data/read/mget*",
                "indices:data/read/field_caps",
                "indices:data/read/field_caps*",
                "indices:data/read/msearch",
                "indices:data/read/scroll"
            )
            .on(MARVELOUS_SONGS)
    );

    private static final String BOTH_INDEX_ALIAS = "both-indices";
    private static final String FORBIDDEN_INDEX_ALIAS = "forbidden-index";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_USER)
        .anonymousAuth(false)
        .doNotFailOnForbidden(true)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(MARVELOUS_SONGS).id(ID_1).source(SONGS[0].asMap()))
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(MARVELOUS_SONGS).id(ID_2).source(SONGS[1].asMap()))
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(MARVELOUS_SONGS).id(ID_3).source(SONGS[2].asMap()))
                .actionGet();

            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(HORRIBLE_SONGS).id(ID_4).source(SONGS[3].asMap()))
                .actionGet();

            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(MARVELOUS_SONGS, HORRIBLE_SONGS).alias(BOTH_INDEX_ALIAS)
                    )
                )
                .actionGet();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(HORRIBLE_SONGS).alias(FORBIDDEN_INDEX_ALIAS)
                    )
                )
                .actionGet();

        }
    }

    @Test
    public void shouldPerformSimpleSearch_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(
                new String[] { MARVELOUS_SONGS, HORRIBLE_SONGS },
                QUERY_TITLE_MAGNUM_OPUS
            );

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    private static void assertThatContainOneSong(SearchResponse searchResponse, String documentId, String title) {
        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
        assertThat(searchResponse, searchHitsContainDocumentWithId(0, MARVELOUS_SONGS, documentId));
        assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, title));
    }

    @Test
    public void shouldPerformSimpleSearch_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(HORRIBLE_SONGS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentsViaIndexPattern_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(BOTH_INDEX_PATTERN, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    @Test
    public void shouldSearchForDocumentsViaIndexPattern_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(HORRIBLE_SONGS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAlias_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(BOTH_INDEX_ALIAS, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(FORBIDDEN_INDEX_ALIAS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAll_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAll_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_POISON);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(0));
        }
    }

    @Test
    public void shouldMGetDocument_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            MultiGetRequest request = new MultiGetRequest().add(BOTH_INDEX_PATTERN, ID_1).add(BOTH_INDEX_PATTERN, ID_4);

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses, arrayWithSize(2));
            MultiGetItemResponse firstResult = responses[0];
            MultiGetItemResponse secondResult = responses[1];
            assertThat(firstResult.getFailure(), nullValue());
            assertThat(secondResult.getFailure(), nullValue());
            assertThat(
                firstResult.getResponse(),
                allOf(containDocument(MARVELOUS_SONGS, ID_1), documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS))
            );
            assertThat(secondResult.getResponse(), containOnlyDocumentId(MARVELOUS_SONGS, ID_4));
        }
    }

    @Test
    public void shouldMGetDocument_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            MultiGetRequest request = new MultiGetRequest().add(HORRIBLE_SONGS, ID_4);

            assertThatThrownBy(() -> restHighLevelClient.mget(request, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldMSearchDocument_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(BOTH_INDEX_PATTERN, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(BOTH_INDEX_PATTERN, QUERY_TITLE_NEXT_SONG));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            MultiSearchResponse.Item[] responses = response.getResponses();
            assertThat(responses, Matchers.arrayWithSize(2));
            assertThat(responses[0].getFailure(), nullValue());
            assertThat(responses[1].getFailure(), nullValue());

            assertThat(responses[0].getResponse(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(responses[0].getResponse(), searchHitsContainDocumentWithId(0, MARVELOUS_SONGS, ID_1));
            assertThat(responses[1].getResponse(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_NEXT_SONG));
            assertThat(responses[1].getResponse(), searchHitsContainDocumentWithId(0, MARVELOUS_SONGS, ID_3));
        }
    }

    @Test
    public void shouldMSearchDocument_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(FORBIDDEN_INDEX_ALIAS, QUERY_TITLE_POISON));

            assertThatThrownBy(() -> restHighLevelClient.msearch(request, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldGetFieldCapabilities_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(MARVELOUS_SONGS, HORRIBLE_SONGS).fields(FIELD_TITLE);

            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response.get(), aMapWithSize(1));
            assertThat(response.getIndices(), arrayWithSize(1));
            assertThat(response.getField(FIELD_TITLE), hasKey("text"));
            assertThat(response.getIndices(), arrayContainingInAnyOrder(MARVELOUS_SONGS));
        }
    }

    @Test
    public void shouldGetFieldCapabilities_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(HORRIBLE_SONGS).fields(FIELD_TITLE);

            assertThatThrownBy(() -> restHighLevelClient.fieldCaps(request, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldScrollOverSearchResults_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(BOTH_INDEX_PATTERN, 2);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);
            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(scrollResponse, numberOfTotalHitsIsEqualTo(3));
            assertThat(scrollResponse, numberOfHitsInPageIsEqualTo(1));
        }
    }

    @Test
    public void shouldScrollOverSearchResults_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(HORRIBLE_SONGS, 2);
            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldPerformAggregation_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            final String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(BOTH_INDEX_PATTERN, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
        }
    }

    @Test
    public void shouldPerformAggregation_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            final String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(HORRIBLE_SONGS, aggregationName, FIELD_STARS);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldPerformStatAggregation_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            final String aggregationName = "statsStars";
            SearchRequest searchRequest = statsAggregationRequest(BOTH_INDEX_ALIAS, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "stats"));
        }
    }

    @Test
    public void shouldPerformStatAggregation_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            final String aggregationName = "statsStars";
            SearchRequest searchRequest = statsAggregationRequest(HORRIBLE_SONGS, aggregationName, FIELD_STARS);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

}
