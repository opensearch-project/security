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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.stream.Collectors;

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
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.http.HttpStatus.SC_CREATED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
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
            "indices:data/read/scroll",
            "cluster:monitor/state",
            "cluster:monitor/health",
            "cluster:monitor/term"
        )
            .indexPermissions(
                "indices:data/read/search",
                "indices:data/read/mget*",
                "indices:data/read/field_caps",
                "indices:data/read/field_caps*",
                "indices:data/read/msearch",
                "indices:data/read/scroll",
                "indices:monitor/settings/get",
                "indices:monitor/stats",
                "indices:admin/aliases/get"
            )
            .on(MARVELOUS_SONGS)
    );

    private static final User STATS_USER = new User("stats_user").roles(
        new Role("test_role").clusterPermissions("cluster:monitor/*").indexPermissions("read", "indices:monitor/*").on("hi1")
    );

    private static final String BOTH_INDEX_ALIAS = "both-indices";
    private static final String FORBIDDEN_INDEX_ALIAS = "forbidden-index";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_USER, STATS_USER)
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

    @Test
    public void shouldPerformCatIndices_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            Request getIndicesRequest = new Request("GET", "/_cat/indices");
            // High level client doesn't support _cat/_indices API
            Response getIndicesResponse = restHighLevelClient.getLowLevelClient().performRequest(getIndicesRequest);
            List<String> indexes = new BufferedReader(new InputStreamReader(getIndicesResponse.getEntity().getContent())).lines()
                .collect(Collectors.toList());

            assertThat(indexes.size(), equalTo(1));
            assertThat(indexes.get(0), containsString("marvelous_songs"));
        }
    }

    @Test
    public void shouldPerformCatAliases_positive() throws IOException {
        // DNFOF works for limited access user
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            Request getAliasesRequest = new Request("GET", "/_cat/aliases");
            Response getAliasesResponse = restHighLevelClient.getLowLevelClient().performRequest(getAliasesRequest);
            List<String> aliases = new BufferedReader(new InputStreamReader(getAliasesResponse.getEntity().getContent())).lines()
                .collect(Collectors.toList());

            // Does not fail on forbidden, but alias response only contains index which user has access to
            assertThat(getAliasesResponse.getStatusLine().getStatusCode(), equalTo(200));
            assertThat(aliases.size(), equalTo(1));
            assertThat(aliases.get(0), containsString("marvelous_songs"));
            assertThat(aliases.get(0), not(containsString("horrible_songs")));

        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            Request getAliasesRequest = new Request("GET", "/_cat/aliases");
            Response getAliasesResponse = restHighLevelClient.getLowLevelClient().performRequest(getAliasesRequest);
            List<String> aliases = new BufferedReader(new InputStreamReader(getAliasesResponse.getEntity().getContent())).lines()
                .collect(Collectors.toList());

            // Admin has access to all
            assertThat(getAliasesResponse.getStatusLine().getStatusCode(), equalTo(200));
            // Aliases have one entry for each index
            // This response is [(both-indices: marvelous_songs), (both-indices: horrible_songs), (forbidden-index: horrible_songs)]
            assertThat(aliases.size(), equalTo(3));
            assertThat(aliases, hasItem(containsString("marvelous_songs")));
            assertThat(aliases, hasItem(containsString("horrible_songs")));

        }
    }

    @Test
    public void checkStatsApi() {
        // As admin creates 2 documents in different indices, can find both indices in search, cat indice & stats APIs
        try (final TestRestClient client = cluster.getRestClient(ADMIN_USER.getName(), ADMIN_USER.getPassword())) {
            final HttpResponse createDoc1 = client.postJson("hi1/_doc?refresh=true", "{\"hi\":\"Hello1\"}");
            createDoc1.assertStatusCode(SC_CREATED);
            final HttpResponse createDoc2 = client.postJson("hi2/_doc?refresh=true", "{\"hi\":\"Hello2\"}");
            createDoc2.assertStatusCode(SC_CREATED);

            final HttpResponse search = client.postJson("hi*/_search", "{}");
            assertThat("Unexpected document results in search:" + search.getBody(), search.getBody(), containsString("2"));

            final HttpResponse catIndices = client.get("_cat/indices");
            assertThat("Expected cat indices: " + catIndices.getBody(), catIndices.getBody(), containsString("hi1"));
            assertThat("Expected cat indices: " + catIndices.getBody(), catIndices.getBody(), containsString("hi2"));

            final HttpResponse stats = client.get("hi*/_stats?filter_path=indices.*.uuid");
            assertThat("Expected stats indices: " + stats.getBody(), stats.getBody(), containsString("hi1"));
            assertThat("Expected stats indices: " + stats.getBody(), stats.getBody(), containsString("hi2"));
        }

        // As user who can only see the index "hi1" make sure that DNFOF is filtering out "hi2"
        try (final TestRestClient client = cluster.getRestClient(STATS_USER.getName(), STATS_USER.getPassword())) {
            final HttpResponse search = client.postJson("hi*/_search", "{}");
            assertThat("Unexpected document results in search:" + search.getBody(), search.getBody(), containsString("1"));

            final HttpResponse catIndices = client.get("_cat/indices");
            assertThat("Expected cat indices: " + catIndices.getBody(), catIndices.getBody(), containsString("hi1"));
            assertThat("Unexpected cat indices: " + catIndices.getBody(), catIndices.getBody(), not(containsString("hi2")));

            final HttpResponse stats = client.get("hi*/_stats?filter_path=indices.*.uuid");
            assertThat("Expected stats indices: " + stats.getBody(), stats.getBody(), containsString("hi1"));
            assertThat("Unexpected stats indices: " + stats.getBody(), stats.getBody(), not(containsString("hi2")));
        }
    }
}
