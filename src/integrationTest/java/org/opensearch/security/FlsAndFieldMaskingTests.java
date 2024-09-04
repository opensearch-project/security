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
import org.hamcrest.Matcher;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
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
import org.opensearch.index.mapper.SourceFieldMapper;
import org.opensearch.index.mapper.size.SizeFieldMapper;
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugin.mapper.MapperSizePlugin;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.metrics.ParsedAvg;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.log.LogsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.ARTIST_FIRST;
import static org.opensearch.security.Song.ARTIST_STRING;
import static org.opensearch.security.Song.ARTIST_TWINS;
import static org.opensearch.security.Song.FIELD_ARTIST;
import static org.opensearch.security.Song.FIELD_GENRE;
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
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitDoesContainField;
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

    static final TestSecurityConfig.Role ROLE_ONLY_FIELD_TITLE_FLS = new TestSecurityConfig.Role("example_inclusive_fls")
        .clusterPermissions("cluster_composite_ops_ro")
        .indexPermissions("read")
        .fls(FIELD_TITLE)
        .on(FIRST_INDEX_NAME);

    static final TestSecurityConfig.Role ROLE_NO_FIELD_TITLE_FLS = new TestSecurityConfig.Role("example_exclusive_fls").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").fls(String.format("~%s", FIELD_TITLE)).on(FIRST_INDEX_NAME);

    static final TestSecurityConfig.Role ROLE_ONLY_FIELD_TITLE_MASKED = new TestSecurityConfig.Role("example_mask").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").maskedFields(FIELD_TITLE.concat("::/(?<=.{1})./::").concat(MASK_VALUE)).on(FIRST_INDEX_NAME);

    /**
     * Example user with fls filter in which the user can only see the {@link Song#FIELD_TITLE} field.
     */
    static final TestSecurityConfig.User USER_ONLY_FIELD_TITLE_FLS = new TestSecurityConfig.User("inclusive_fls_user").roles(
        ROLE_ONLY_FIELD_TITLE_FLS
    );

    /**
     * Example user with fls filter in which the user can see every field but the {@link Song#FIELD_TITLE} field.
     */
    static final TestSecurityConfig.User USER_NO_FIELD_TITLE_FLS = new TestSecurityConfig.User("exclusive_fls_user").roles(
        ROLE_NO_FIELD_TITLE_FLS
    );

    /**
     * Example user in which {@link Song#FIELD_TITLE} field is masked.
     */
    static final TestSecurityConfig.User USER_ONLY_FIELD_TITLE_MASKED = new TestSecurityConfig.User("masked_user").roles(
        ROLE_ONLY_FIELD_TITLE_MASKED
    );

    /**
     * Example user with fls filter in which the user can only see the {@link Song#FIELD_TITLE} field and can see every field but the {@link Song#FIELD_TITLE} field- should default to showing no fields.
     */
    static final TestSecurityConfig.User USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS = new TestSecurityConfig.User("inclusive_exclusive_fls_user")
        .roles(ROLE_ONLY_FIELD_TITLE_FLS, ROLE_NO_FIELD_TITLE_FLS);

    /**
     * Example user with fls filter in which the user can only see the {@link Song#FIELD_TITLE} field and in which {@link Song#FIELD_TITLE} field is masked.
     */
    static final TestSecurityConfig.User USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED = new TestSecurityConfig.User(
        "inclusive_masked_user"
    ).roles(ROLE_ONLY_FIELD_TITLE_FLS, ROLE_ONLY_FIELD_TITLE_MASKED);

    /**
     *  Example user with fls filter in which the user can see every field but the {@link Song#FIELD_TITLE} field and in which {@link Song#FIELD_TITLE} field is masked- {@link Song#FIELD_TITLE} field should not be visible.
     */
    static final TestSecurityConfig.User USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED = new TestSecurityConfig.User(
        "exclusive_masked_user"
    ).roles(ROLE_NO_FIELD_TITLE_FLS, ROLE_ONLY_FIELD_TITLE_MASKED);

    /**
     * Example user with fls filter in which the user can only see the {@link Song#FIELD_TITLE} field and can see every field but the {@link Song#FIELD_TITLE} field and in which {@link Song#FIELD_TITLE} field is masked- should default to showing no fields.
     */
    static final TestSecurityConfig.User USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED = new TestSecurityConfig.User(
        "inclusive_exclusive_masked_user"
    ).roles(ROLE_ONLY_FIELD_TITLE_FLS, ROLE_NO_FIELD_TITLE_FLS, ROLE_ONLY_FIELD_TITLE_MASKED);

    static final TestSecurityConfig.User USER_FLS_INCLUDE_STARS = new TestSecurityConfig.User("fls_include_stars_reader").roles(
        new TestSecurityConfig.Role("fls_include_stars_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .fls(FIELD_STARS)
            .on("*")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()))
        )
        .plugin(MapperSizePlugin.class)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(
            ADMIN_USER,
            ALL_INDICES_MASKED_TITLE_ARTIST_READER,
            MASKED_ARTIST_LYRICS_READER,
            ALL_INDICES_STRING_ARTIST_READER,
            ALL_INDICES_STARS_LESS_THAN_ZERO_READER,
            TWINS_FIRST_ARTIST_READER,
            USER_ONLY_FIELD_TITLE_FLS,
            USER_NO_FIELD_TITLE_FLS,
            USER_ONLY_FIELD_TITLE_MASKED,
            USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS,
            USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED,
            USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED,
            USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED,
            USER_FLS_INCLUDE_STARS
        )
        .build();

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.security.configuration.SecurityFlsDlsIndexSearcherWrapper");

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
            client.admin()
                .indices()
                .create(new CreateIndexRequest(indexName).mapping(Map.of("_size", Map.of("enabled", true))))
                .actionGet();
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

    static void assertSearchHitsDoNotContainField(SearchResponse response, String excludedField) {
        assertThat(response, isSuccessfulSearchResponse());
        assertThat(response.getHits().getHits().length, greaterThan(0));
        IntStream.range(0, response.getHits().getHits().length)
            .boxed()
            .forEach(index -> assertThat(response, searchHitDoesNotContainField(index, excludedField)));
    }

    private static void assertSearchHitsDoContainField(SearchResponse response, String includedField) {
        assertThat(response, isSuccessfulSearchResponse());
        assertThat(response.getHits().getHits().length, greaterThan(0));
        IntStream.range(0, response.getHits().getHits().length)
            .boxed()
            .forEach(index -> assertThat(response, searchHitDoesContainField(index, includedField)));
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

    @Test
    public void testGetDocumentWithNoTitleFieldOrOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        GetRequest getRequest = new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ONLY_FIELD_TITLE_FLS)) {
            assertGetForFLSRestrictions(restHighLevelClient, getRequest, true);
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_NO_FIELD_TITLE_FLS)) {
            assertGetForFLSRestrictions(restHighLevelClient, getRequest, false);
        }
    }

    private void assertGetForFLSRestrictions(RestHighLevelClient restHighLevelClient, GetRequest getRequest, boolean shouldShowFieldTitle)
        throws IOException, Exception {
        // if shouldShowFieldTitle == true, we check that only the title field is fetched; if shouldShowFieldTitle == false, we check that
        // only the title field is
        // ignored
        GetResponse getResponse = restHighLevelClient.get(getRequest, DEFAULT);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));

        Matcher<GetResponse> containsTitleField = documentContainField(
            FIELD_TITLE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()
        );
        Matcher<GetResponse> containsArtistField = documentContainField(
            FIELD_ARTIST,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
        );
        Matcher<GetResponse> containsLyricsField = documentContainField(
            FIELD_LYRICS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
        );
        Matcher<GetResponse> containsStarsField = documentContainField(
            FIELD_STARS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
        );
        Matcher<GetResponse> containsGenreField = documentContainField(
            FIELD_GENRE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
        );

        assertThat(getResponse, shouldShowFieldTitle ? containsTitleField : not(containsTitleField));
        assertThat(getResponse, shouldShowFieldTitle ? not(containsArtistField) : containsArtistField);
        assertThat(getResponse, shouldShowFieldTitle ? not(containsLyricsField) : containsLyricsField);
        assertThat(getResponse, shouldShowFieldTitle ? not(containsStarsField) : containsStarsField);
        assertThat(getResponse, shouldShowFieldTitle ? not(containsGenreField) : containsGenreField);
    }

    @Test
    public void testMultiGetDocumentWithNoTitleFieldOrOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        MultiGetRequest multiGetRequest = new MultiGetRequest();
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2));

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ONLY_FIELD_TITLE_FLS)) {
            assertMGetForFLSRestrictions(restHighLevelClient, multiGetRequest, true);
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_NO_FIELD_TITLE_FLS)) {
            assertMGetForFLSRestrictions(restHighLevelClient, multiGetRequest, false);
        }
    }

    private void assertMGetForFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        MultiGetRequest multiGetRequest,
        boolean shouldShowFieldTitle
    ) throws IOException, Exception {
        // if shouldShowFieldTitle == true, we check that only the title field is fetched; if shouldShowFieldTitle == false, we check that
        // only the title field is
        // ignored
        MultiGetResponse multiGetResponse = restHighLevelClient.mget(multiGetRequest, DEFAULT);
        List<GetResponse> getResponses = Arrays.stream(multiGetResponse.getResponses())
            .map(MultiGetItemResponse::getResponse)
            .collect(Collectors.toList());

        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));

        Matcher<GetResponse> documentOneContainsTitleField = documentContainField(
            FIELD_TITLE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()
        );
        Matcher<GetResponse> documentOneContainsArtistField = documentContainField(
            FIELD_ARTIST,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
        );
        Matcher<GetResponse> documentOneContainsLyricsField = documentContainField(
            FIELD_LYRICS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
        );
        Matcher<GetResponse> documentOneContainsStarsField = documentContainField(
            FIELD_STARS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
        );
        Matcher<GetResponse> documentOneContainsGenreField = documentContainField(
            FIELD_GENRE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
        );
        Matcher<GetResponse> documentTwoContainsTitleField = documentContainField(
            FIELD_TITLE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle()
        );
        Matcher<GetResponse> documentTwoContainsArtistField = documentContainField(
            FIELD_ARTIST,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()
        );
        Matcher<GetResponse> documentTwoContainsLyricsField = documentContainField(
            FIELD_LYRICS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()
        );
        Matcher<GetResponse> documentTwoContainsStarsField = documentContainField(
            FIELD_STARS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars()
        );
        Matcher<GetResponse> documentTwoContainsGenreField = documentContainField(
            FIELD_GENRE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre()
        );

        assertThat(
            getResponses,
            shouldShowFieldTitle ? hasItem(documentOneContainsTitleField) : not(hasItem(documentOneContainsTitleField))
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentOneContainsArtistField)) : hasItem(documentOneContainsArtistField)
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentOneContainsLyricsField)) : hasItem(documentOneContainsLyricsField)
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentOneContainsStarsField)) : hasItem(documentOneContainsStarsField)
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentOneContainsGenreField)) : hasItem(documentOneContainsGenreField)
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? hasItem(documentTwoContainsTitleField) : not(hasItem(documentTwoContainsTitleField))
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentTwoContainsArtistField)) : hasItem(documentTwoContainsArtistField)
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentTwoContainsLyricsField)) : hasItem(documentTwoContainsLyricsField)
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentTwoContainsStarsField)) : hasItem(documentTwoContainsStarsField)
        );
        assertThat(
            getResponses,
            shouldShowFieldTitle ? not(hasItem(documentTwoContainsGenreField)) : hasItem(documentTwoContainsGenreField)
        );
    }

    @Test
    public void testSearchDocumentWithWithNoTitleFieldOrOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ONLY_FIELD_TITLE_FLS)) {
            assertSearchForFLSRestrictions(restHighLevelClient, searchRequest, true);
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_NO_FIELD_TITLE_FLS)) {
            assertSearchForFLSRestrictions(restHighLevelClient, searchRequest, false);
        }
    }

    private void assertSearchForFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        SearchRequest searchRequest,
        boolean shouldShowFieldTitle
    ) throws IOException, Exception {
        // if shouldShowFieldTitle == true, we check that only the title field is fetched; if shouldShowFieldTitle == false, we check that
        // only the title field is
        // ignored
        SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));

        IntStream.range(0, 4).forEach(hitIndex -> {
            assertThat(
                searchResponse,
                shouldShowFieldTitle
                    ? searchHitContainsFieldWithValue(hitIndex, FIELD_TITLE, SONGS[hitIndex].getTitle())
                    : searchHitDoesNotContainField(hitIndex, FIELD_TITLE)
            );
            assertThat(
                searchResponse,
                shouldShowFieldTitle
                    ? searchHitDoesNotContainField(hitIndex, FIELD_ARTIST)
                    : searchHitContainsFieldWithValue(hitIndex, FIELD_ARTIST, SONGS[hitIndex].getArtist())
            );
            assertThat(
                searchResponse,
                shouldShowFieldTitle
                    ? searchHitDoesNotContainField(hitIndex, FIELD_LYRICS)
                    : searchHitContainsFieldWithValue(hitIndex, FIELD_LYRICS, SONGS[hitIndex].getLyrics())
            );
            assertThat(
                searchResponse,
                shouldShowFieldTitle
                    ? searchHitDoesNotContainField(hitIndex, FIELD_STARS)
                    : searchHitContainsFieldWithValue(hitIndex, FIELD_STARS, SONGS[hitIndex].getStars())
            );
            assertThat(
                searchResponse,
                shouldShowFieldTitle
                    ? searchHitDoesNotContainField(hitIndex, FIELD_GENRE)
                    : searchHitContainsFieldWithValue(hitIndex, FIELD_GENRE, SONGS[hitIndex].getGenre())
            );
        });
    }

    @Test
    public void testGetDocumentWithTitleFieldMaskingRestriction() throws IOException, Exception {
        GetRequest getRequest = new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ONLY_FIELD_TITLE_MASKED)) {
            assertProperGetResponsesForTitleFieldMaskingRestriction(restHighLevelClient, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingRestriction(RestHighLevelClient restHighLevelClient, GetRequest getRequest)
        throws IOException, Exception {
        GetResponse getResponse = restHighLevelClient.get(getRequest, DEFAULT);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        assertThat(
            getResponse,
            documentContainField(FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()))
        );
        assertThat(getResponse, documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()));
        assertThat(getResponse, documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()));
        assertThat(getResponse, documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()));
        assertThat(getResponse, documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()));
    }

    @Test
    public void testMultiGetDocumentWithTitleFieldMaskingRestriction() throws IOException, Exception {
        MultiGetRequest multiGetRequest = new MultiGetRequest();
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2));

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ONLY_FIELD_TITLE_MASKED)) {
            assertProperMultiGetResponseForTitleFieldMaskingRestriction(restHighLevelClient, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingRestriction(
        RestHighLevelClient restHighLevelClient,
        MultiGetRequest multiGetRequest
    ) throws IOException, Exception {
        MultiGetResponse multiGetResponse = restHighLevelClient.mget(multiGetRequest, DEFAULT);
        List<GetResponse> getResponses = Arrays.stream(multiGetResponse.getResponses())
            .map(MultiGetItemResponse::getResponse)
            .collect(Collectors.toList());

        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));
        assertThat(
            getResponses,
            hasItem(
                documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()))
        );
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre())));
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingRestriction() throws IOException, Exception {
        SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ONLY_FIELD_TITLE_MASKED)) {
            assertProperSearchResponseForTitleFieldMaskingRestriction(restHighLevelClient, searchRequest);
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingRestriction(
        RestHighLevelClient restHighLevelClient,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
        IntStream.range(0, 4).forEach(hitIndex -> {
            assertThat(
                searchResponse,
                searchHitContainsFieldWithValue(hitIndex, FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(SONGS[hitIndex].getTitle()))
            );
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_ARTIST, SONGS[hitIndex].getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_LYRICS, SONGS[hitIndex].getLyrics()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_STARS, SONGS[hitIndex].getStars()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_GENRE, SONGS[hitIndex].getGenre()));
        });
    }

    @Test
    public void testGetDocumentWithNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        GetRequest getRequest = new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS)) {
            assertProperGetResponsesForOnlyAndNoTitleFLSRestrictions(restHighLevelClient, getRequest);
        }
    }

    private void assertProperGetResponsesForOnlyAndNoTitleFLSRestrictions(RestHighLevelClient restHighLevelClient, GetRequest getRequest)
        throws IOException, Exception {
        GetResponse getResponse = restHighLevelClient.get(getRequest, DEFAULT);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title
        assertThat(getResponse, not(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())));
        assertThat(getResponse, documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()));
        assertThat(getResponse, documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()));
        assertThat(getResponse, documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()));
        assertThat(getResponse, documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()));
    }

    @Test
    public void testMultiGetDocumentWithNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        MultiGetRequest multiGetRequest = new MultiGetRequest();
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2));

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS)) {
            assertProperMultiGetResponseForOnlyAndNoTitleFLSRestrictions(restHighLevelClient, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForOnlyAndNoTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        MultiGetRequest multiGetRequest
    ) throws IOException, Exception {
        MultiGetResponse multiGetResponse = restHighLevelClient.mget(multiGetRequest, DEFAULT);
        List<GetResponse> getResponses = Arrays.stream(multiGetResponse.getResponses())
            .map(MultiGetItemResponse::getResponse)
            .collect(Collectors.toList());

        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()))
        );
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre())));
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle())))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()))
        );
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre())));
    }

    @Test
    public void testSearchDocumentWithWithNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS)) {
            assertProperSearchResponseForOnlyAndNoTitleFLSRestrictions(restHighLevelClient, searchRequest);
        }
    }

    private void assertProperSearchResponseForOnlyAndNoTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title
        IntStream.range(0, 4).forEach(hitIndex -> {
            assertThat(searchResponse, searchHitDoesNotContainField(hitIndex, FIELD_TITLE));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_ARTIST));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_LYRICS));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_STARS));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_GENRE));
        });
    }

    @Test
    public void testGetDocumentWithTitleFieldMaskingAndOnlyTitleFLSRestrictions() throws IOException, Exception {
        GetRequest getRequest = new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)
        ) {
            assertProperGetResponsesForTitleFieldMaskingAndOnlyTitleFLSRestrictions(restHighLevelClient, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingAndOnlyTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        GetRequest getRequest
    ) throws IOException, Exception {
        GetResponse getResponse = restHighLevelClient.get(getRequest, DEFAULT);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        assertThat(
            getResponse,
            documentContainField(FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()))
        );
        assertThat(getResponse, not(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist())));
        assertThat(getResponse, not(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics())));
        assertThat(getResponse, not(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars())));
        assertThat(getResponse, not(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre())));
    }

    @Test
    public void testMultiGetDocumentWithTitleFieldMaskingAndOnlyTitleFLSRestrictions() throws IOException, Exception {
        MultiGetRequest multiGetRequest = new MultiGetRequest();
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2));

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)
        ) {
            assertProperMultiGetResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(restHighLevelClient, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        MultiGetRequest multiGetRequest
    ) throws IOException, Exception {
        MultiGetResponse multiGetResponse = restHighLevelClient.mget(multiGetRequest, DEFAULT);
        List<GetResponse> getResponses = Arrays.stream(multiGetResponse.getResponses())
            .map(MultiGetItemResponse::getResponse)
            .collect(Collectors.toList());

        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));
        assertThat(
            getResponses,
            hasItem(
                documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre())))
        );
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingAndOnlyTitleFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)
        ) {
            assertProperSearchResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(restHighLevelClient, searchRequest);
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
        IntStream.range(0, 4).forEach(hitIndex -> {
            assertThat(
                searchResponse,
                searchHitContainsFieldWithValue(hitIndex, FIELD_TITLE, VALUE_TO_MASKED_VALUE.apply(SONGS[hitIndex].getTitle()))
            );
            assertThat(searchResponse, searchHitDoesNotContainField(hitIndex, FIELD_ARTIST));
            assertThat(searchResponse, searchHitDoesNotContainField(hitIndex, FIELD_LYRICS));
            assertThat(searchResponse, searchHitDoesNotContainField(hitIndex, FIELD_STARS));
            assertThat(searchResponse, searchHitDoesNotContainField(hitIndex, FIELD_GENRE));
        });
    }

    @Test
    public void testGetDocumentWithTitleFieldMaskingAndNoTitleFLSRestrictions() throws IOException, Exception {
        GetRequest getRequest = new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)
        ) {
            assertProperGetResponsesForTitleFieldMaskingAndNoTitleFLSRestrictions(restHighLevelClient, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingAndNoTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        GetRequest getRequest
    ) throws IOException, Exception {
        GetResponse getResponse = restHighLevelClient.get(getRequest, DEFAULT);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        assertThat(getResponse, not(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())));
        assertThat(getResponse, documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()));
        assertThat(getResponse, documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()));
        assertThat(getResponse, documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()));
        assertThat(getResponse, documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()));
    }

    @Test
    public void testMultiGetDocumentWithTitleFieldMaskingAndNoTitleFLSRestrictions() throws IOException, Exception {
        MultiGetRequest multiGetRequest = new MultiGetRequest();
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2));

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)
        ) {
            assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(restHighLevelClient, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        MultiGetRequest multiGetRequest
    ) throws IOException, Exception {
        MultiGetResponse multiGetResponse = restHighLevelClient.mget(multiGetRequest, DEFAULT);
        List<GetResponse> getResponses = Arrays.stream(multiGetResponse.getResponses())
            .map(MultiGetItemResponse::getResponse)
            .collect(Collectors.toList());

        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())))
        );
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle())))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()))
        );
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre())));
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingAndNoTitleFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)
        ) {
            assertProperSearchResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(restHighLevelClient, searchRequest);
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
        IntStream.range(0, 4).forEach(hitIndex -> {
            assertThat(searchResponse, searchHitDoesNotContainField(hitIndex, FIELD_TITLE));
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_ARTIST, SONGS[hitIndex].getArtist()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_LYRICS, SONGS[hitIndex].getLyrics()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_STARS, SONGS[hitIndex].getStars()));
            assertThat(searchResponse, searchHitContainsFieldWithValue(hitIndex, FIELD_GENRE, SONGS[hitIndex].getGenre()));
        });
    }

    @Test
    public void testGetDocumentWithTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        GetRequest getRequest = new GetRequest(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED
            )
        ) {
            assertProperGetResponsesForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(restHighLevelClient, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        GetRequest getRequest
    ) throws IOException, Exception {
        GetResponse getResponse = restHighLevelClient.get(getRequest, DEFAULT);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title, and since there
        // is no title the masking role has no effect
        assertThat(getResponse, not(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())));
        assertThat(getResponse, documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()));
        assertThat(getResponse, documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()));
        assertThat(getResponse, documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()));
        assertThat(getResponse, documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()));
    }

    @Test
    public void testMultiGetDocumentWithTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        MultiGetRequest multiGetRequest = new MultiGetRequest();
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        multiGetRequest.add(new MultiGetRequest.Item(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2));

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED
            )
        ) {
            assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
                restHighLevelClient,
                multiGetRequest
            );
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        MultiGetRequest multiGetRequest
    ) throws IOException, Exception {
        MultiGetResponse multiGetResponse = restHighLevelClient.mget(multiGetRequest, DEFAULT);
        List<GetResponse> getResponses = Arrays.stream(multiGetResponse.getResponses())
            .map(MultiGetItemResponse::getResponse)
            .collect(Collectors.toList());

        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title, and since there
        // is no title the masking role has no effect
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()))
        );
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre())));
        assertThat(
            getResponses,
            not(hasItem(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle())))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()))
        );
        assertThat(
            getResponses,
            hasItem(documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()))
        );
        assertThat(getResponses, hasItem(documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars())));
        assertThat(getResponses, hasItem(documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre())));
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED
            )
        ) {
            assertProperSearchResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
                restHighLevelClient,
                searchRequest
            );
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
        RestHighLevelClient restHighLevelClient,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title, and since there
        // is no title the masking role has no effect
        IntStream.range(0, 4).forEach(hitIndex -> {
            assertThat(searchResponse, searchHitDoesNotContainField(hitIndex, FIELD_TITLE));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_ARTIST));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_LYRICS));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_STARS));
            assertThat(searchResponse, searchHitDoesContainField(hitIndex, FIELD_GENRE));
        });
    }

    @Test
    public void flsWithIncludesRulesIncludesFieldMappersFromPlugins() throws IOException {
        String indexName = "fls_includes_index";
        List<String> docIds = createIndexWithDocs(indexName, SONGS[0], SONGS[1]);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_FLS_INCLUDE_STARS)) {
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            MatchAllQueryBuilder matchAllQueryBuilder = QueryBuilders.matchAllQuery();
            searchSourceBuilder.storedFields(List.of(SizeFieldMapper.NAME, SourceFieldMapper.NAME));
            searchSourceBuilder.query(matchAllQueryBuilder);
            searchRequest.source(searchSourceBuilder);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchHitsDoContainField(searchResponse, FIELD_STARS);
            assertThat(searchResponse.toString(), containsString(SizeFieldMapper.NAME));
            assertSearchHitsDoNotContainField(searchResponse, FIELD_ARTIST);
        }
    }

    @Test
    public void testFlsOnAClosedAndReopenedIndex() throws IOException {
        String indexName = "fls_includes_index2";
        List<String> docIds = createIndexWithDocs(indexName, SONGS[0], SONGS[1]);

        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.post(indexName + "/_close");
            client.post(indexName + "/_open");
            logsRule.assertThatContainExactly(indexName + " was closed. Setting metadataFields to empty. Closed index is not searchable.");
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_FLS_INCLUDE_STARS)) {
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            MatchAllQueryBuilder matchAllQueryBuilder = QueryBuilders.matchAllQuery();
            searchSourceBuilder.storedFields(List.of(SizeFieldMapper.NAME, SourceFieldMapper.NAME));
            searchSourceBuilder.query(matchAllQueryBuilder);
            searchRequest.source(searchSourceBuilder);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchHitsDoContainField(searchResponse, FIELD_STARS);
            assertThat(searchResponse.toString(), containsString(SizeFieldMapper.NAME));
            assertSearchHitsDoNotContainField(searchResponse, FIELD_ARTIST);
        }
    }

}
