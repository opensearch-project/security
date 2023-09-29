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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.metrics.ParsedAvg;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.ARTIST_FIRST;
import static org.opensearch.security.Song.ARTIST_STRING;
import static org.opensearch.security.Song.ARTIST_TWINS;
import static org.opensearch.security.Song.FIELD_ARTIST;
import static org.opensearch.security.Song.FIELD_LYRICS;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.opensearch.security.Song.FIELD_TITLE;
import static org.opensearch.security.Song.QUERY_TITLE_NEXT_SONG;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.Song.TITLE_NEXT_SONG;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryByIdsRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsExactlyIndices;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsFieldWithNameAndType;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.numberOfFieldsIsEqualTo;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containDocument;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentDoesNotContainField;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.isSuccessfulMultiGetResponse;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.numberOfGetItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.isSuccessfulMultiSearchResponse;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.numberOfSearchItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitDoesNotContainField;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentWithId;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FlsAndFieldMaskingTests {

    static final String FIRST_INDEX_ID_SONG_1 = "INDEX_1_S1";
    static final String FIRST_INDEX_ID_SONG_2 = "INDEX_1_S2";
    static final String FIRST_INDEX_ID_SONG_3 = "INDEX_1_S3";
    static final String FIRST_INDEX_ID_SONG_4 = "INDEX_1_S4";
    static final String SECOND_INDEX_ID_SONG_1 = "INDEX_2_S1";
    static final String SECOND_INDEX_ID_SONG_2 = "INDEX_2_S2";
    static final String SECOND_INDEX_ID_SONG_3 = "INDEX_2_S3";
    static final String SECOND_INDEX_ID_SONG_4 = "INDEX_2_S4";

    static final String INDEX_NAME_SUFFIX = "-test-index";
    static final String FIRST_INDEX_NAME = "first".concat(INDEX_NAME_SUFFIX);
    static final String SECOND_INDEX_NAME = "second".concat(INDEX_NAME_SUFFIX);
    static final String FIRST_INDEX_ALIAS = FIRST_INDEX_NAME.concat("-alias");
    static final String SECOND_INDEX_ALIAS = SECOND_INDEX_NAME.concat("-alias");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE = FIRST_INDEX_NAME.concat("-filtered-by-next-song-title");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_TWINS_ARTIST = FIRST_INDEX_NAME.concat("-filtered-by-twins-artist");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_FIRST_ARTIST = FIRST_INDEX_NAME.concat("-filtered-by-first-artist");
    static final String ALL_INDICES_ALIAS = "_all";

    static final String MASK_VALUE = "*";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    /**
    * User who is allowed to see all fields on all indices. Values of the title and artist fields should be masked.
    */
    static final TestSecurityConfig.User ALL_INDICES_MASKED_TITLE_ARTIST_READER = new TestSecurityConfig.User("masked_artist_title_reader")
        .roles(
            new TestSecurityConfig.Role("masked_artist_title_reader").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields(
                    FIELD_TITLE.concat("::/(?<=.{1})./::").concat(MASK_VALUE),
                    FIELD_ARTIST.concat("::/(?<=.{1})./::").concat(MASK_VALUE)
                )
                .on("*")
        );

    /**
    * User who is allowed to see all fields on indices {@link #FIRST_INDEX_NAME} and {@link #SECOND_INDEX_NAME}.
    * <ul>
    *     <li>values of the artist and lyrics fields should be masked on index {@link #FIRST_INDEX_NAME}</li>
    *     <li>values of the lyrics field should be masked on index {@link #SECOND_INDEX_NAME}</li>
    * </ul>
    */
    static final TestSecurityConfig.User MASKED_ARTIST_LYRICS_READER = new TestSecurityConfig.User("masked_title_artist_lyrics_reader")
        .roles(
            new TestSecurityConfig.Role("masked_title_artist_lyrics_reader").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields(
                    FIELD_ARTIST.concat("::/(?<=.{1})./::").concat(MASK_VALUE),
                    FIELD_LYRICS.concat("::/(?<=.{1})./::").concat(MASK_VALUE)
                )
                .on(FIRST_INDEX_NAME),
            new TestSecurityConfig.Role("masked_lyrics_reader").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .maskedFields(FIELD_LYRICS.concat("::/(?<=.{1})./::").concat(MASK_VALUE))
                .on(SECOND_INDEX_NAME)
        );

    /**
    * Function that converts field value to value masked with {@link #MASK_VALUE}
    */
    static final Function<String, String> VALUE_TO_MASKED_VALUE = value -> value.substring(0, 1)
        .concat(MASK_VALUE.repeat(value.length() - 1));

    /**
    * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_STRING}.
    */
    static final TestSecurityConfig.User ALL_INDICES_STRING_ARTIST_READER = new TestSecurityConfig.User("string_artist_reader").roles(
        new TestSecurityConfig.Role("string_artist_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_STRING))
            .on("*")
    );

    /**
    * User who is allowed to see documents on index:
    * <ul>
    *     <li>{@link #FIRST_INDEX_NAME} where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_TWINS}</li>
    *     <li>{@link #SECOND_INDEX_NAME} where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_FIRST}</li>
    * </ul>
    */
    static final TestSecurityConfig.User TWINS_FIRST_ARTIST_READER = new TestSecurityConfig.User("twins_first_artist_reader").roles(
        new TestSecurityConfig.Role("twins_artist_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_TWINS))
            .on(FIRST_INDEX_NAME),
        new TestSecurityConfig.Role("first_artist_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_FIRST))
            .on(SECOND_INDEX_NAME)
    );

    /**
    * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_STARS} is less than zero.
    */
    static final TestSecurityConfig.User ALL_INDICES_STARS_LESS_THAN_ZERO_READER = new TestSecurityConfig.User(
        "stars_less_than_zero_reader"
    ).roles(
        new TestSecurityConfig.Role("stars_less_than_zero_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"range\":{\"%s\":{\"lt\":%d}}}", FIELD_STARS, 0))
            .on("*")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()))
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(
            ADMIN_USER,
            ALL_INDICES_MASKED_TITLE_ARTIST_READER,
            MASKED_ARTIST_LYRICS_READER,
            ALL_INDICES_STRING_ARTIST_READER,
            ALL_INDICES_STARS_LESS_THAN_ZERO_READER,
            TWINS_FIRST_ARTIST_READER
        )
        .build();

    /**
    * Function that returns id assigned to song with title equal to given title or throws {@link RuntimeException}
    * when no song matches.
    */
    static final BiFunction<Map<String, Song>, String, String> FIND_ID_OF_SONG_WITH_TITLE = (map, title) -> map.entrySet()
        .stream()
        .filter(entry -> title.equals(entry.getValue().getTitle()))
        .findAny()
        .map(Map.Entry::getKey)
        .orElseThrow(() -> new RuntimeException("Cannot find id of song with title: " + title));

    /**
    * Function that returns id assigned to song with artist equal to given artist or throws {@link RuntimeException}
    * when no song matches.
    */
    static final BiFunction<Map<String, Song>, String, String> FIND_ID_OF_SONG_WITH_ARTIST = (map, artist) -> map.entrySet()
        .stream()
        .filter(entry -> artist.equals(entry.getValue().getArtist()))
        .findAny()
        .map(Map.Entry::getKey)
        .orElseThrow(() -> new RuntimeException("Cannot find id of song with artist: " + artist));

    static final TreeMap<String, Song> FIRST_INDEX_SONGS_BY_ID = new TreeMap<>() {
        {
            put(FIRST_INDEX_ID_SONG_1, SONGS[0]);
            put(FIRST_INDEX_ID_SONG_2, SONGS[1]);
            put(FIRST_INDEX_ID_SONG_3, SONGS[2]);
            put(FIRST_INDEX_ID_SONG_4, SONGS[3]);
        }
    };

    static final TreeMap<String, Song> SECOND_INDEX_SONGS_BY_ID = new TreeMap<>() {
        {
            put(SECOND_INDEX_ID_SONG_1, SONGS[3]);
            put(SECOND_INDEX_ID_SONG_2, SONGS[2]);
            put(SECOND_INDEX_ID_SONG_3, SONGS[1]);
            put(SECOND_INDEX_ID_SONG_4, SONGS[0]);
        }
    };

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            FIRST_INDEX_SONGS_BY_ID.forEach((id, song) -> {
                client.prepareIndex(FIRST_INDEX_NAME).setId(id).setRefreshPolicy(IMMEDIATE).setSource(song.asMap()).get();
            });

            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(FIRST_INDEX_NAME).alias(FIRST_INDEX_ALIAS)
                    )
                )
                .actionGet();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).index(FIRST_INDEX_NAME)
                            .alias(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE)
                            .filter(QueryBuilders.queryStringQuery(QUERY_TITLE_NEXT_SONG))
                    )
                )
                .actionGet();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).index(FIRST_INDEX_NAME)
                            .alias(FIRST_INDEX_ALIAS_FILTERED_BY_TWINS_ARTIST)
                            .filter(QueryBuilders.queryStringQuery(String.format("%s:%s", FIELD_ARTIST, ARTIST_TWINS)))
                    )
                )
                .actionGet();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).index(FIRST_INDEX_NAME)
                            .alias(FIRST_INDEX_ALIAS_FILTERED_BY_FIRST_ARTIST)
                            .filter(QueryBuilders.queryStringQuery(String.format("%s:%s", FIELD_ARTIST, ARTIST_FIRST)))
                    )
                )
                .actionGet();

            SECOND_INDEX_SONGS_BY_ID.forEach((id, song) -> {
                client.prepareIndex(SECOND_INDEX_NAME).setId(id).setRefreshPolicy(IMMEDIATE).setSource(song.asMap()).get();
            });
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(SECOND_INDEX_NAME).alias(SECOND_INDEX_ALIAS)
                    )
                )
                .actionGet();
        }
    }

    @Test
    public void flsEnabledFieldsAreHiddenForNormalUsers() throws IOException {
        String indexName = "fls_index";
        String indexAlias = "fls_index_alias";
        String indexFilteredAlias = "fls_index_filtered_alias";
        TestSecurityConfig.Role userRole = new TestSecurityConfig.Role("fls_exclude_stars_reader").clusterPermissions(
            "cluster_composite_ops_ro"
        ).indexPermissions("read").fls("~".concat(FIELD_STARS)).on("*");
        TestSecurityConfig.User user = createUserWithRole("fls_user", userRole);
        List<String> docIds = createIndexWithDocs(indexName, SONGS[0], SONGS[1]);
        addAliasToIndex(indexName, indexAlias);
        addAliasToIndex(
            indexName,
            indexFilteredAlias,
            QueryBuilders.queryStringQuery(String.format("%s:%s", FIELD_ARTIST, SONGS[0].getArtist()))
        );

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(user)) {
            // search
            SearchResponse searchResponse = restHighLevelClient.search(new SearchRequest(indexName), DEFAULT);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search with index pattern
            searchResponse = restHighLevelClient.search(new SearchRequest("*".concat(indexName)), DEFAULT);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search via alias
            searchResponse = restHighLevelClient.search(new SearchRequest(indexAlias), DEFAULT);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search via filtered alias
            searchResponse = restHighLevelClient.search(new SearchRequest(indexFilteredAlias), DEFAULT);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search via all indices alias
            searchResponse = restHighLevelClient.search(new SearchRequest(ALL_INDICES_ALIAS), DEFAULT);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // scroll
            searchResponse = restHighLevelClient.search(searchRequestWithScroll(indexName, 1), DEFAULT);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);
            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);

            assertSearchHitsDoNotContainField(scrollResponse, FIELD_STARS);

            // aggregate data and compute avg
            String aggregationName = "averageStars";
            searchResponse = restHighLevelClient.search(averageAggregationRequest(indexName, aggregationName, FIELD_STARS), DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(Double.POSITIVE_INFINITY)); // user cannot see the STARS field

            // get document
            GetResponse getResponse = restHighLevelClient.get(new GetRequest(indexName, docIds.get(0)), DEFAULT);

            assertThat(getResponse, documentDoesNotContainField(FIELD_STARS));

            // multi get
            for (String index : List.of(indexName, indexAlias)) {
                MultiGetRequest multiGetRequest = new MultiGetRequest();
                docIds.forEach(id -> multiGetRequest.add(new MultiGetRequest.Item(index, id)));

                MultiGetResponse multiGetResponse = restHighLevelClient.mget(multiGetRequest, DEFAULT);

                List<GetResponse> getResponses = Arrays.stream(multiGetResponse.getResponses())
                    .map(MultiGetItemResponse::getResponse)
                    .collect(Collectors.toList());
                assertThat(getResponses, everyItem(documentDoesNotContainField(FIELD_STARS)));
            }

            // multi search
            for (String index : List.of(indexName, indexAlias)) {
                MultiSearchRequest multiSearchRequest = new MultiSearchRequest();
                docIds.forEach(id -> multiSearchRequest.add(queryByIdsRequest(index, id)));
                MultiSearchResponse multiSearchResponse = restHighLevelClient.msearch(multiSearchRequest, DEFAULT);

                assertThat(multiSearchResponse, isSuccessfulMultiSearchResponse());
                List<MultiSearchResponse.Item> itemResponses = List.of(multiSearchResponse.getResponses());
                itemResponses.forEach(item -> assertSearchHitsDoNotContainField(item.getResponse(), FIELD_STARS));
            }

            // field capabilities
            FieldCapabilitiesResponse fieldCapsResponse = restHighLevelClient.fieldCaps(
                new FieldCapabilitiesRequest().indices(indexName).fields(FIELD_TITLE, FIELD_STARS),
                DEFAULT
            );
            assertThat(fieldCapsResponse.getField(FIELD_STARS), nullValue());
        }
    }

    private static List<String> createIndexWithDocs(String indexName, Song... songs) {
        try (Client client = cluster.getInternalNodeClient()) {
            return Stream.of(songs).map(song -> {
                IndexResponse response = client.index(new IndexRequest(indexName).setRefreshPolicy(IMMEDIATE).source(song.asMap()))
                    .actionGet();
                return response.getId();
            }).collect(Collectors.toList());
        }
    }

    private static void addAliasToIndex(String indexName, String alias) {
        addAliasToIndex(indexName, alias, QueryBuilders.matchAllQuery());
    }

    private static void addAliasToIndex(String indexName, String alias, QueryBuilder filterQuery) {
        try (Client client = cluster.getInternalNodeClient()) {
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(indexName).alias(alias).filter(filterQuery)
                    )
                )
                .actionGet();
        }
    }

    private static TestSecurityConfig.User createUserWithRole(String userName, TestSecurityConfig.Role role) {
        TestSecurityConfig.User user = new TestSecurityConfig.User(userName);
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.createRole(role.getName(), role).assertStatusCode(201);
            client.createUser(user.getName(), user).assertStatusCode(201);
            client.assignRoleToUser(user.getName(), role.getName()).assertStatusCode(200);
        }
        return user;
    }

    private static void assertSearchHitsDoNotContainField(SearchResponse response, String excludedField) {
        assertThat(response, isSuccessfulSearchResponse());
        assertThat(response.getHits().getHits().length, greaterThan(0));
        IntStream.range(0, response.getHits().getHits().length)
            .boxed()
            .forEach(index -> assertThat(response, searchHitDoesNotContainField(index, excludedField)));
    }

    @Test
    public void searchForDocuments() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_1;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest(FIRST_INDEX_NAME, songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_2;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest = queryByIdsRequest(SECOND_INDEX_NAME, songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, song.getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }
    }

    @Test
    public void searchForDocumentsWithIndexPattern() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_2;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest("*".concat(FIRST_INDEX_NAME), songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_3;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest = queryByIdsRequest("*".concat(SECOND_INDEX_NAME), songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, song.getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }
    }

    @Test
    public void searchForDocumentsViaAlias() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_3;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest(FIRST_INDEX_ALIAS, songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_4;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest = queryByIdsRequest("*".concat(SECOND_INDEX_ALIAS), songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, song.getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }
    }

    @Test
    public void searchForDocumentsViaFilteredAlias() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIND_ID_OF_SONG_WITH_TITLE.apply(FIRST_INDEX_SONGS_BY_ID, TITLE_NEXT_SONG);
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }
    }

    @Test
    public void searchForDocumentsViaAllIndicesAlias() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ALL_INDICES_MASKED_TITLE_ARTIST_READER)) {
            String songId = FIRST_INDEX_ID_SONG_4;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest(ALL_INDICES_ALIAS, songId);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(song.getTitle())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, song.getLyrics()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_1;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);

            searchRequest = queryByIdsRequest(ALL_INDICES_ALIAS, songId);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(song.getTitle())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, song.getLyrics()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }
    }

    @Test
    public void scrollOverSearchResults() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_SONGS_BY_ID.firstKey();
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = searchRequestWithScroll(FIRST_INDEX_NAME, 1);
            searchRequest.source().sort("_id", SortOrder.ASC);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
            assertThat(scrollResponse, isSuccessfulSearchResponse());
            assertThat(scrollResponse, containNotEmptyScrollingId());
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, songId));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, song.getTitle()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_STARS, song.getStars()));
        }
    }

    @Test
    public void aggregateDataAndComputeAverage() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String aggregationName = "averageStars";
            Double expectedValue = FIRST_INDEX_SONGS_BY_ID.values()
                .stream()
                .mapToDouble(Song::getStars)
                .average()
                .orElseThrow(() -> new RuntimeException("Cannot compute average stars - list of docs is empty"));
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(expectedValue));
        }
    }

    @Test
    public void getDocument() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_4;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);
            GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, songId), DEFAULT);

            assertThat(response, containDocument(FIRST_INDEX_NAME, songId));
            assertThat(response, documentContainField(FIELD_TITLE, song.getTitle()));
            assertThat(response, documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(response, documentContainField(FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
            assertThat(response, documentContainField(FIELD_STARS, song.getStars()));

            songId = SECOND_INDEX_ID_SONG_1;
            song = SECOND_INDEX_SONGS_BY_ID.get(songId);
            response = restHighLevelClient.get(new GetRequest(SECOND_INDEX_NAME, songId), DEFAULT);

            assertThat(response, containDocument(SECOND_INDEX_NAME, songId));
            assertThat(response, documentContainField(FIELD_TITLE, song.getTitle()));
            assertThat(response, documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
            assertThat(response, documentContainField(FIELD_ARTIST, song.getArtist()));
            assertThat(response, documentContainField(FIELD_STARS, song.getStars()));
        }
    }

    @Test
    public void multiGetDocuments() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            List<List<String>> indicesToCheck = List.of(
                List.of(FIRST_INDEX_NAME, SECOND_INDEX_NAME),
                List.of(FIRST_INDEX_ALIAS, SECOND_INDEX_ALIAS)
            );
            String firstSongId = FIRST_INDEX_ID_SONG_1;
            Song firstSong = FIRST_INDEX_SONGS_BY_ID.get(firstSongId);
            String secondSongId = SECOND_INDEX_ID_SONG_2;
            Song secondSong = SECOND_INDEX_SONGS_BY_ID.get(secondSongId);

            for (List<String> indices : indicesToCheck) {
                MultiGetRequest request = new MultiGetRequest();
                request.add(new MultiGetRequest.Item(indices.get(0), firstSongId));
                request.add(new MultiGetRequest.Item(indices.get(1), secondSongId));
                MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

                assertThat(response, isSuccessfulMultiGetResponse());
                assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

                MultiGetItemResponse[] responses = response.getResponses();
                assertThat(
                    responses[0].getResponse(),
                    allOf(
                        containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1),
                        documentContainField(FIELD_TITLE, firstSong.getTitle()),
                        documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(firstSong.getLyrics())),
                        documentContainField(FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(firstSong.getArtist())),
                        documentContainField(FIELD_STARS, firstSong.getStars())
                    )
                );
                assertThat(
                    responses[1].getResponse(),
                    allOf(
                        containDocument(SECOND_INDEX_NAME, secondSongId),
                        documentContainField(FIELD_TITLE, secondSong.getTitle()),
                        documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(secondSong.getLyrics())),
                        documentContainField(FIELD_ARTIST, secondSong.getArtist()),
                        documentContainField(FIELD_STARS, secondSong.getStars())
                    )
                );
            }
        }
    }

    @Test
    public void multiSearchDocuments() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            List<List<String>> indicesToCheck = List.of(
                List.of(FIRST_INDEX_NAME, SECOND_INDEX_NAME),
                List.of(FIRST_INDEX_ALIAS, SECOND_INDEX_ALIAS)
            );
            String firstSongId = FIRST_INDEX_ID_SONG_3;
            Song firstSong = FIRST_INDEX_SONGS_BY_ID.get(firstSongId);
            String secondSongId = SECOND_INDEX_ID_SONG_4;
            Song secondSong = SECOND_INDEX_SONGS_BY_ID.get(secondSongId);

            for (List<String> indices : indicesToCheck) {
                MultiSearchRequest request = new MultiSearchRequest();
                request.add(queryByIdsRequest(indices.get(0), firstSongId));
                request.add(queryByIdsRequest(indices.get(1), secondSongId));
                MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

                assertThat(response, isSuccessfulMultiSearchResponse());
                assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

                MultiSearchResponse.Item[] responses = response.getResponses();

                assertThat(
                    responses[0].getResponse(),
                    allOf(
                        searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, firstSongId),
                        searchHitContainsFieldWithValue(0, FIELD_TITLE, firstSong.getTitle()),
                        searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(firstSong.getLyrics())),
                        searchHitContainsFieldWithValue(0, FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(firstSong.getArtist())),
                        searchHitContainsFieldWithValue(0, FIELD_STARS, firstSong.getStars())
                    )
                );
                assertThat(
                    responses[1].getResponse(),
                    allOf(
                        searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, secondSongId),
                        searchHitContainsFieldWithValue(0, FIELD_TITLE, secondSong.getTitle()),
                        searchHitContainsFieldWithValue(0, FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(secondSong.getLyrics())),
                        searchHitContainsFieldWithValue(0, FIELD_ARTIST, secondSong.getArtist()),
                        searchHitContainsFieldWithValue(0, FIELD_STARS, secondSong.getStars())
                    )
                );
            }
        }
    }

    @Test
    public void getFieldCapabilities() throws IOException {
        // FIELD MASKING
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(MASKED_ARTIST_LYRICS_READER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(FIRST_INDEX_NAME)
                .fields(FIELD_ARTIST, FIELD_TITLE, FIELD_LYRICS);
            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, containsExactlyIndices(FIRST_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(3));
            assertThat(response, containsFieldWithNameAndType(FIELD_ARTIST, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_LYRICS, "text"));
        }
    }

}
