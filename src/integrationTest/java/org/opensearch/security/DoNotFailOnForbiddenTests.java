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
import java.util.List;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.opensearch._types.query_dsl.QueryBuilders;
import org.opensearch.client.opensearch.cat.AliasesResponse;
import org.opensearch.client.opensearch.cat.IndicesResponse;
import org.opensearch.client.opensearch.cat.aliases.AliasesRecord;
import org.opensearch.client.opensearch.cat.indices.IndicesRecord;
import org.opensearch.client.opensearch.core.FieldCapsRequest;
import org.opensearch.client.opensearch.core.FieldCapsResponse;
import org.opensearch.client.opensearch.core.MgetRequest;
import org.opensearch.client.opensearch.core.MgetResponse;
import org.opensearch.client.opensearch.core.MsearchRequest;
import org.opensearch.client.opensearch.core.MsearchResponse;
import org.opensearch.client.opensearch.core.ScrollRequest;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.mget.MultiGetResponseItem;
import org.opensearch.client.opensearch.core.msearch.MultisearchBody;
import org.opensearch.client.opensearch.core.msearch.MultisearchHeader;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.OpenSearchClientProvider.CloseableOpenSearchClient;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.transport.client.Client;

import static org.apache.http.HttpStatus.SC_CREATED;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.hamcrest.Matchers.not;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
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
import static org.opensearch.test.framework.client.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.client.SearchRequestFactory.statsAggregationRequest;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.client.GetResultMatchers.containDocument;
import static org.opensearch.test.framework.matcher.client.GetResultMatchers.containOnlyDocumentId;
import static org.opensearch.test.framework.matcher.client.GetResultMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.numberOfHitsInPageIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitsContainDocumentWithId;
import static org.opensearch.test.framework.matcher.client.TransportExceptionMatchers.statusException;

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
            "cluster:monitor/health"
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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(
                new String[] { MARVELOUS_SONGS, HORRIBLE_SONGS },
                QUERY_TITLE_MAGNUM_OPUS
            );

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    private static void assertThatContainOneSong(SearchResponse<?> searchResponse, String documentId, String title) {
        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
        assertThat(searchResponse, searchHitsContainDocumentWithId(0, MARVELOUS_SONGS, documentId));
        assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, title));
    }

    @Test
    public void shouldPerformSimpleSearch_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(HORRIBLE_SONGS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentsViaIndexPattern_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(BOTH_INDEX_PATTERN, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    @Test
    public void shouldSearchForDocumentsViaIndexPattern_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(HORRIBLE_SONGS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAlias_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(BOTH_INDEX_ALIAS, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAlias_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(FORBIDDEN_INDEX_ALIAS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAll_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThatContainOneSong(searchResponse, ID_1, TITLE_MAGNUM_OPUS);
        }
    }

    @Test
    public void shouldSearchForDocumentsViaAll_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_POISON);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(0));
        }
    }

    @Test
    public void shouldMGetDocument_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            MgetRequest request = MgetRequest.of(
                r -> r.docs(d -> d.index(MARVELOUS_SONGS).id(ID_1)).docs(d -> d.index(MARVELOUS_SONGS).id(ID_4))
            );

            MgetResponse<?> response = client.mget(request, Map.class);

            var responses = response.docs();
            assertThat(responses, iterableWithSize(2));
            MultiGetResponseItem<?> firstResult = responses.get(0);
            MultiGetResponseItem<?> secondResult = responses.get(1);
            assertThat(firstResult.isResult(), is(true));
            assertThat(secondResult.isResult(), is(true));
            assertThat(
                firstResult.result(),
                allOf(containDocument(MARVELOUS_SONGS, ID_1), documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS))
            );
            assertThat(secondResult.result(), containOnlyDocumentId(MARVELOUS_SONGS, ID_4));
        }
    }

    @Test
    public void shouldMGetDocument_partial() throws Exception {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            MgetRequest request = MgetRequest.of(
                r -> r.docs(d -> d.index(MARVELOUS_SONGS).id(ID_1)).docs(d -> d.index(HORRIBLE_SONGS).id(ID_4))
            );

            MgetResponse<?> response = client.mget(request, Map.class);

            var responses = response.docs();
            assertThat(responses, iterableWithSize(2));
            MultiGetResponseItem<?> firstResult = responses.get(0);
            MultiGetResponseItem<?> secondResult = responses.get(1);
            assertThat(firstResult.isResult(), is(true));
            assertThat(
                firstResult.result(),
                allOf(containDocument(MARVELOUS_SONGS, ID_1), documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS))
            );
            assertThat(secondResult.failure().error().reason(), containsString("no permissions for [indices:data/read/mget[shard]]"));
        }
    }

    @Test
    public void shouldMGetDocument_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            MgetRequest request = MgetRequest.of(r -> r.index(HORRIBLE_SONGS).ids(ID_4));
            MgetResponse<?> response = client.mget(request, Map.class);
            var responses = response.docs();
            assertThat(responses, iterableWithSize(1));
            MultiGetResponseItem<?> firstResult = responses.get(0);
            assertThat(firstResult.failure().error().reason(), containsString("no permissions for [indices:data/read/mget[shard]]"));
        }
    }

    @Test
    public void shouldMSearchDocument_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            MsearchRequest request = MsearchRequest.of(
                r -> r.searches(
                    s -> s.header(MultisearchHeader.of(h -> h.index(BOTH_INDEX_PATTERN)))
                        .body(
                            MultisearchBody.of(b -> b.query(QueryBuilders.queryString().query(QUERY_TITLE_MAGNUM_OPUS).build().toQuery()))
                        )
                )
                    .searches(
                        s -> s.header(MultisearchHeader.of(h -> h.index(BOTH_INDEX_PATTERN)))
                            .body(
                                MultisearchBody.of(b -> b.query(QueryBuilders.queryString().query(QUERY_TITLE_NEXT_SONG).build().toQuery()))
                            )
                    )
            );

            MsearchResponse<?> response = client.msearch(request, Map.class);
            var responses = response.responses();
            assertThat(responses, iterableWithSize(2));
            assertThat(responses.get(0).isResult(), is(true));
            assertThat(responses.get(1).isResult(), is(true));

            assertThat(responses.get(0).result(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(responses.get(0).result(), searchHitsContainDocumentWithId(0, MARVELOUS_SONGS, ID_1));
            assertThat(responses.get(1).result(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_NEXT_SONG));
            assertThat(responses.get(1).result(), searchHitsContainDocumentWithId(0, MARVELOUS_SONGS, ID_3));
        }
    }

    @Test
    public void shouldMSearchDocument_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            MsearchRequest request = MsearchRequest.of(
                r -> r.searches(
                    s -> s.header(MultisearchHeader.of(f -> f.index(FORBIDDEN_INDEX_ALIAS)))
                        .body(MultisearchBody.of(b -> b.query(QueryBuilders.queryString().query(QUERY_TITLE_POISON).build().toQuery())))
                )
            );
            MsearchResponse<?> response = client.msearch(request, Map.class);
            var responses = response.responses();
            assertThat(responses, iterableWithSize(1));
            assertThat(responses.get(0).failure().error().reason(), containsString("no permissions for [indices:data/read/search]"));
        }
    }

    @Test
    public void shouldGetFieldCapabilities_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            FieldCapsRequest request = FieldCapsRequest.of(r -> r.index(MARVELOUS_SONGS, HORRIBLE_SONGS).fields(FIELD_TITLE));

            FieldCapsResponse response = client.fieldCaps(request);

            assertThat(response.fields(), aMapWithSize(1));
            assertThat(response.indices(), iterableWithSize(1));
            assertThat(response.fields().get(FIELD_TITLE), hasKey("text"));
            assertThat(response.indices(), containsInAnyOrder(MARVELOUS_SONGS));
        }
    }

    @Test
    public void shouldGetFieldCapabilities_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            FieldCapsRequest request = FieldCapsRequest.of(r -> r.index(HORRIBLE_SONGS).fields(FIELD_TITLE));

            assertThatThrownBy(() -> client.fieldCaps(request), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldScrollOverSearchResults_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(BOTH_INDEX_PATTERN, 2);
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);
            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            ScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse<?> scrollResponse = client.scroll(scrollRequest, Map.class);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(scrollResponse, numberOfTotalHitsIsEqualTo(3));
            assertThat(scrollResponse, numberOfHitsInPageIsEqualTo(1));
        }
    }

    @Test
    public void shouldScrollOverSearchResults_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(HORRIBLE_SONGS, 2);
            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldPerformAggregation_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            final String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(BOTH_INDEX_PATTERN, aggregationName, FIELD_STARS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
        }
    }

    @Test
    public void shouldPerformAggregation_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            final String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(HORRIBLE_SONGS, aggregationName, FIELD_STARS);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldPerformStatAggregation_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            final String aggregationName = "statsStars";
            SearchRequest searchRequest = statsAggregationRequest(BOTH_INDEX_ALIAS, aggregationName, FIELD_STARS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "stats"));
        }
    }

    @Test
    public void shouldPerformStatAggregation_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            final String aggregationName = "statsStars";
            SearchRequest searchRequest = statsAggregationRequest(HORRIBLE_SONGS, aggregationName, FIELD_STARS);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldPerformCatIndices_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            IndicesResponse getIndicesResponse = client.cat().indices();
            List<String> indexes = getIndicesResponse.valueBody().stream().map(IndicesRecord::index).toList();

            assertThat(indexes.size(), equalTo(1));
            assertThat(indexes.get(0), containsString("marvelous_songs"));
        }
    }

    @Test
    public void shouldPerformCatAliases_positive() throws IOException {
        // DNFOF works for limited access user
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_USER)) {
            AliasesResponse getAliasesResponse = client.cat().aliases();
            List<String> aliases = getAliasesResponse.valueBody().stream().map(AliasesRecord::index).sorted().toList();

            // Does not fail on forbidden, but alias response only contains index which user has access to
            assertThat(aliases.size(), equalTo(1));
            assertThat(aliases, hasItem(containsString("marvelous_songs")));
            assertThat(aliases, not(hasItem(containsString("horrible_songs"))));

        }

        try (CloseableOpenSearchClient client = cluster.getClient(ADMIN_USER)) {
            AliasesResponse getAliasesResponse = client.cat().aliases();
            List<String> aliases = getAliasesResponse.valueBody().stream().map(AliasesRecord::index).sorted().toList();

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
