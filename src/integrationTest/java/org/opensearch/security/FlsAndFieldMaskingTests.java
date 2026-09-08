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
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.hamcrest.Matcher;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.aggregations.Aggregate;
import org.opensearch.client.opensearch._types.aggregations.AvgAggregate;
import org.opensearch.client.opensearch.core.FieldCapsRequest;
import org.opensearch.client.opensearch.core.FieldCapsResponse;
import org.opensearch.client.opensearch.core.GetRequest;
import org.opensearch.client.opensearch.core.GetResponse;
import org.opensearch.client.opensearch.core.MgetRequest;
import org.opensearch.client.opensearch.core.MgetResponse;
import org.opensearch.client.opensearch.core.MsearchRequest;
import org.opensearch.client.opensearch.core.MsearchResponse;
import org.opensearch.client.opensearch.core.ScrollRequest;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.mget.MultiGetResponseItem;
import org.opensearch.client.opensearch.core.search.Hit;
import org.opensearch.index.mapper.SourceFieldMapper;
import org.opensearch.index.mapper.size.SizeFieldMapper;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugin.mapper.MapperSizePlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.OpenSearchClientProvider.CloseableOpenSearchClient;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.log.LogsRule;
import org.opensearch.test.framework.matcher.client.GetResponseMatchers;
import org.opensearch.test.framework.matcher.client.MultiGetResponseItemMatchers;
import org.opensearch.test.framework.matcher.client.MultiSearchResponseItemMatchers;
import org.opensearch.transport.client.Client;

import static org.apache.http.HttpStatus.SC_OK;
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
import static org.opensearch.test.framework.client.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.queryByIdsRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.matcher.client.FieldCapsResponseMatchers.containsExactlyIndices;
import static org.opensearch.test.framework.matcher.client.FieldCapsResponseMatchers.containsFieldWithNameAndType;
import static org.opensearch.test.framework.matcher.client.FieldCapsResponseMatchers.numberOfFieldsIsEqualTo;
import static org.opensearch.test.framework.matcher.client.GetResultMatchers.containDocument;
import static org.opensearch.test.framework.matcher.client.GetResultMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.client.GetResultMatchers.documentDoesNotContainField;
import static org.opensearch.test.framework.matcher.client.MultiGetResponseMatchers.isSuccessfulMultiGetResponse;
import static org.opensearch.test.framework.matcher.client.MultiGetResponseMatchers.numberOfGetItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.client.MultiSearchResponseMatchers.isSuccessfulMultiSearchResponse;
import static org.opensearch.test.framework.matcher.client.MultiSearchResponseMatchers.numberOfSearchItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitDoesContainField;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitDoesNotContainField;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitsContainDocumentWithId;

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

    static final TestSecurityConfig.Role ROLE_NO_FIELD_TITLE_WILDCARD_INDEX_FLS = new TestSecurityConfig.Role("example_exclusive_fls")
        .clusterPermissions("cluster_composite_ops_ro")
        .indexPermissions("read", "indices:admin/mappings/get")
        .fls(String.format("~%s", FIELD_TITLE))
        .on("*");

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
     * Example user with fls filter in which the user can see every field but the {@link Song#FIELD_TITLE} field.
     */
    static final TestSecurityConfig.User USER_NO_FIELD_TITLE_WILDCARD_INDEX_FLS = new TestSecurityConfig.User("exclusive_wildcard_fls_user")
        .roles(ROLE_NO_FIELD_TITLE_WILDCARD_INDEX_FLS);

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
            USER_NO_FIELD_TITLE_WILDCARD_INDEX_FLS,
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

        try (CloseableOpenSearchClient client = cluster.getClient(user)) {
            // search
            SearchResponse<?> searchResponse = client.search(SearchRequest.of(r -> r.index(indexName)), Map.class);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search with index pattern
            searchResponse = client.search(SearchRequest.of(r -> r.index("*".concat(indexName))), Map.class);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search via alias
            searchResponse = client.search(SearchRequest.of(r -> r.index(indexAlias)), Map.class);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search via filtered alias
            searchResponse = client.search(SearchRequest.of(r -> r.index(indexFilteredAlias)), Map.class);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search via all indices alias
            searchResponse = client.search(SearchRequest.of(r -> r.index(ALL_INDICES_ALIAS)), Map.class);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // scroll
            searchResponse = client.search(searchRequestWithScroll(indexName, 1), Map.class);

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            ScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);
            SearchResponse<?> scrollResponse = client.scroll(scrollRequest, Map.class);

            assertSearchHitsDoNotContainField(scrollResponse, FIELD_STARS);

            // aggregate data and compute avg
            String aggregationName = "averageStars";
            searchResponse = client.search(averageAggregationRequest(indexName, aggregationName, FIELD_STARS), Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregate actualAggregation = searchResponse.aggregations().get(aggregationName);
            assertThat(actualAggregation._get(), instanceOf(AvgAggregate.class));
            assertThat(actualAggregation.avg().value(), is(nullValue())); // user cannot see the STARS field

            // get document
            GetResponse<?> getResponse = client.get(GetRequest.of(r -> r.index(indexName).id(docIds.get(0))), Map.class);

            assertThat(getResponse, documentDoesNotContainField(FIELD_STARS));

            // multi get
            for (String index : List.of(indexName, indexAlias)) {
                MgetRequest multiGetRequest = MgetRequest.of(r -> r.index(index).ids(docIds));
                MgetResponse<?> multiGetResponse = client.mget(multiGetRequest, Map.class);

                var getResponses = multiGetResponse.docs();
                assertThat(getResponses, everyItem(MultiGetResponseItemMatchers.documentDoesNotContainField(FIELD_STARS)));
            }

            // multi search
            for (String index : List.of(indexName, indexAlias)) {
                MsearchRequest multiSearchRequest = MsearchRequest.of(
                    r -> r.searches(
                        s -> s.header(h -> h.index(index))
                            .body(
                                b -> b.query(
                                    org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.ids().values(docIds).build().toQuery()
                                )
                            )
                    )
                );
                MsearchResponse<?> multiSearchResponse = client.msearch(multiSearchRequest, Map.class);

                assertThat(multiSearchResponse, isSuccessfulMultiSearchResponse());
                var itemResponses = multiSearchResponse.responses();
                itemResponses.forEach(item -> assertSearchHitsDoNotContainField(item.result(), FIELD_STARS));
            }

            // field capabilities
            FieldCapsResponse fieldCapsResponse = client.fieldCaps(
                FieldCapsRequest.of(r -> r.index(indexName).fields(FIELD_TITLE, FIELD_STARS))
            );
            assertThat(fieldCapsResponse.fields().get(FIELD_STARS), nullValue());
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

    private static void assertSearchHitsDoNotContainField(SearchResponse<?> response, String excludedField) {
        assertThat(response, isSuccessfulSearchResponse());
        assertThat(response.hits().hits().size(), greaterThan(0));
        IntStream.range(0, response.hits().hits().size())
            .forEach(index -> assertThat(response, searchHitDoesNotContainField(index, excludedField)));
    }

    private static void assertSearchHitsDoContainField(SearchResponse<?> response, String includedField) {
        assertThat(response, isSuccessfulSearchResponse());
        assertThat(response.hits().hits().size(), greaterThan(0));
        IntStream.range(0, response.hits().hits().size())
            .forEach(index -> assertThat(response, searchHitDoesContainField(index, includedField)));
    }

    @Test
    public void searchForDocuments() throws IOException {
        // FIELD MASKING
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_1;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest(FIRST_INDEX_NAME, songId);
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
            searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_2;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest("*".concat(FIRST_INDEX_NAME), songId);
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
            searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_ID_SONG_3;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest(FIRST_INDEX_ALIAS, songId);
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
            searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIND_ID_OF_SONG_WITH_TITLE.apply(FIRST_INDEX_SONGS_BY_ID, TITLE_NEXT_SONG);
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = SearchRequest.of(r -> r.index(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE));
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(ALL_INDICES_MASKED_TITLE_ARTIST_READER)) {
            String songId = FIRST_INDEX_ID_SONG_4;
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = queryByIdsRequest(ALL_INDICES_ALIAS, songId);
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
            searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            String songId = FIRST_INDEX_SONGS_BY_ID.firstKey();
            Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);

            SearchRequest searchRequest = searchRequestWithScroll(FIRST_INDEX_NAME, 1);
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            ScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            SearchResponse<?> scrollResponse = client.scroll(scrollRequest, Map.class);
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
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            String aggregationName = "averageStars";
            Double expectedValue = FIRST_INDEX_SONGS_BY_ID.values()
                .stream()
                .mapToDouble(Song::getStars)
                .average()
                .orElseThrow(() -> new RuntimeException("Cannot compute average stars - list of docs is empty"));
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregate actualAggregation = searchResponse.aggregations().get(aggregationName);
            assertThat(actualAggregation._get(), instanceOf(AvgAggregate.class));
            assertThat(actualAggregation.avg().value(), is(expectedValue));
        }
    }

    @Test
    public void getDocument() throws IOException {
        // FIELD MASKING
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            {
                String songId = FIRST_INDEX_ID_SONG_4;
                Song song = FIRST_INDEX_SONGS_BY_ID.get(songId);
                GetResponse<?> response = client.get(GetRequest.of(r -> r.index(FIRST_INDEX_NAME).id(songId)), Map.class);

                assertThat(response, containDocument(FIRST_INDEX_NAME, songId));
                assertThat(response, documentContainField(FIELD_TITLE, song.getTitle()));
                assertThat(response, documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
                assertThat(response, documentContainField(FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(song.getArtist())));
                assertThat(response, documentContainField(FIELD_STARS, song.getStars()));
            }

            {
                String songId = SECOND_INDEX_ID_SONG_1;
                Song song = SECOND_INDEX_SONGS_BY_ID.get(songId);
                GetResponse<?> response = client.get(GetRequest.of(r -> r.index(SECOND_INDEX_NAME).id(songId)), Map.class);

                assertThat(response, containDocument(SECOND_INDEX_NAME, songId));
                assertThat(response, documentContainField(FIELD_TITLE, song.getTitle()));
                assertThat(response, documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(song.getLyrics())));
                assertThat(response, documentContainField(FIELD_ARTIST, song.getArtist()));
                assertThat(response, documentContainField(FIELD_STARS, song.getStars()));
            }
        }
    }

    @Test
    public void multiGetDocuments() throws IOException {
        // FIELD MASKING
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            List<List<String>> indicesToCheck = List.of(
                List.of(FIRST_INDEX_NAME, SECOND_INDEX_NAME),
                List.of(FIRST_INDEX_ALIAS, SECOND_INDEX_ALIAS)
            );
            String firstSongId = FIRST_INDEX_ID_SONG_1;
            Song firstSong = FIRST_INDEX_SONGS_BY_ID.get(firstSongId);
            String secondSongId = SECOND_INDEX_ID_SONG_2;
            Song secondSong = SECOND_INDEX_SONGS_BY_ID.get(secondSongId);

            for (List<String> indices : indicesToCheck) {
                MgetRequest request = MgetRequest.of(
                    r -> r.docs(d -> d.index(indices.get(0)).id(firstSongId)).docs(d -> d.index(indices.get(1)).id(secondSongId))
                );
                MgetResponse<?> response = client.mget(request, Map.class);

                assertThat(response, isSuccessfulMultiGetResponse());
                assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

                var responses = response.docs();
                assertThat(
                    responses.get(0),
                    allOf(
                        MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1),
                        MultiGetResponseItemMatchers.documentContainField(FIELD_TITLE, firstSong.getTitle()),
                        MultiGetResponseItemMatchers.documentContainField(FIELD_LYRICS, VALUE_TO_MASKED_VALUE.apply(firstSong.getLyrics())),
                        MultiGetResponseItemMatchers.documentContainField(FIELD_ARTIST, VALUE_TO_MASKED_VALUE.apply(firstSong.getArtist())),
                        MultiGetResponseItemMatchers.documentContainField(FIELD_STARS, firstSong.getStars())
                    )
                );
                assertThat(
                    responses.get(1),
                    allOf(
                        MultiGetResponseItemMatchers.containDocument(SECOND_INDEX_NAME, secondSongId),
                        MultiGetResponseItemMatchers.documentContainField(FIELD_TITLE, secondSong.getTitle()),
                        MultiGetResponseItemMatchers.documentContainField(
                            FIELD_LYRICS,
                            VALUE_TO_MASKED_VALUE.apply(secondSong.getLyrics())
                        ),
                        MultiGetResponseItemMatchers.documentContainField(FIELD_ARTIST, secondSong.getArtist()),
                        MultiGetResponseItemMatchers.documentContainField(FIELD_STARS, secondSong.getStars())
                    )
                );
            }
        }
    }

    @Test
    public void multiSearchDocuments() throws IOException {
        // FIELD MASKING
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            List<List<String>> indicesToCheck = List.of(
                List.of(FIRST_INDEX_NAME, SECOND_INDEX_NAME),
                List.of(FIRST_INDEX_ALIAS, SECOND_INDEX_ALIAS)
            );
            String firstSongId = FIRST_INDEX_ID_SONG_3;
            Song firstSong = FIRST_INDEX_SONGS_BY_ID.get(firstSongId);
            String secondSongId = SECOND_INDEX_ID_SONG_4;
            Song secondSong = SECOND_INDEX_SONGS_BY_ID.get(secondSongId);

            for (List<String> indices : indicesToCheck) {
                MsearchRequest request = MsearchRequest.of(
                    r -> r.searches(
                        s -> s.header(h -> h.index(indices.get(0)))
                            .body(
                                b -> b.query(
                                    org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.ids()
                                        .values(firstSongId)
                                        .build()
                                        .toQuery()
                                )
                            )
                    )
                        .searches(
                            s -> s.header(h -> h.index(indices.get(1)))
                                .body(
                                    b -> b.query(
                                        org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.ids()
                                            .values(secondSongId)
                                            .build()
                                            .toQuery()
                                    )
                                )
                        )
                );

                MsearchResponse<?> response = client.msearch(request, Map.class);

                assertThat(response, isSuccessfulMultiSearchResponse());
                assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

                var responses = response.responses();

                assertThat(
                    responses.get(0),
                    allOf(
                        MultiSearchResponseItemMatchers.searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, firstSongId),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(0, FIELD_TITLE, firstSong.getTitle()),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(
                            0,
                            FIELD_LYRICS,
                            VALUE_TO_MASKED_VALUE.apply(firstSong.getLyrics())
                        ),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(
                            0,
                            FIELD_ARTIST,
                            VALUE_TO_MASKED_VALUE.apply(firstSong.getArtist())
                        ),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(0, FIELD_STARS, firstSong.getStars())
                    )
                );
                assertThat(
                    responses.get(1),
                    allOf(
                        MultiSearchResponseItemMatchers.searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, secondSongId),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(0, FIELD_TITLE, secondSong.getTitle()),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(
                            0,
                            FIELD_LYRICS,
                            VALUE_TO_MASKED_VALUE.apply(secondSong.getLyrics())
                        ),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(0, FIELD_ARTIST, secondSong.getArtist()),
                        MultiSearchResponseItemMatchers.searchHitContainsFieldWithValue(0, FIELD_STARS, secondSong.getStars())
                    )
                );
            }
        }
    }

    @Test
    public void getFieldCapabilities() throws IOException {
        // FIELD MASKING
        try (CloseableOpenSearchClient client = cluster.getClient(MASKED_ARTIST_LYRICS_READER)) {
            FieldCapsRequest request = FieldCapsRequest.of(r -> r.index(FIRST_INDEX_NAME).fields(FIELD_ARTIST, FIELD_TITLE, FIELD_LYRICS));
            FieldCapsResponse response = client.fieldCaps(request);

            assertThat(response, containsExactlyIndices(FIRST_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(3));
            assertThat(response, containsFieldWithNameAndType(FIELD_ARTIST, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
            assertThat(response, containsFieldWithNameAndType(FIELD_LYRICS, "text"));
        }
    }

    @Test
    public void testGetDocumentWithNoTitleFieldOrOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        GetRequest getRequest = GetRequest.of(r -> r.index(FIRST_INDEX_NAME).id(FIRST_INDEX_ID_SONG_1));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ONLY_FIELD_TITLE_FLS)) {
            assertGetForFLSRestrictions(client, getRequest, true);
        }

        try (CloseableOpenSearchClient client = cluster.getClient(USER_NO_FIELD_TITLE_FLS)) {
            assertGetForFLSRestrictions(client, getRequest, false);
        }
    }

    private void assertGetForFLSRestrictions(OpenSearchClient client, GetRequest getRequest, boolean shouldShowFieldTitle)
        throws IOException, Exception {
        // if shouldShowFieldTitle == true, we check that only the title field is fetched; if shouldShowFieldTitle == false, we check that
        // only the title field is
        // ignored
        GetResponse<?> getResponse = client.get(getRequest, Map.class);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));

        Matcher<GetResponse<?>> containsTitleField = GetResponseMatchers.documentContainField(
            FIELD_TITLE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()
        );
        Matcher<GetResponse<?>> containsArtistField = GetResponseMatchers.documentContainField(
            FIELD_ARTIST,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
        );
        Matcher<GetResponse<?>> containsLyricsField = GetResponseMatchers.documentContainField(
            FIELD_LYRICS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
        );
        Matcher<GetResponse<?>> containsStarsField = GetResponseMatchers.documentContainField(
            FIELD_STARS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
        );
        Matcher<GetResponse<?>> containsGenreField = GetResponseMatchers.documentContainField(
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
        MgetRequest multiGetRequest = MgetRequest.of(r -> r.index(FIRST_INDEX_NAME).ids(FIRST_INDEX_ID_SONG_1, FIRST_INDEX_ID_SONG_2));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ONLY_FIELD_TITLE_FLS)) {
            assertMGetForFLSRestrictions(client, multiGetRequest, true);
        }

        try (CloseableOpenSearchClient client = cluster.getClient(USER_NO_FIELD_TITLE_FLS)) {
            assertMGetForFLSRestrictions(client, multiGetRequest, false);
        }
    }

    private void assertMGetForFLSRestrictions(OpenSearchClient client, MgetRequest multiGetRequest, boolean shouldShowFieldTitle)
        throws IOException, Exception {
        // if shouldShowFieldTitle == true, we check that only the title field is fetched; if shouldShowFieldTitle == false, we check that
        // only the title field is
        // ignored
        MgetResponse<?> multiGetResponse = client.mget(multiGetRequest, Map.class);
        var getResponses = multiGetResponse.docs();

        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));

        Matcher<MultiGetResponseItem<?>> documentOneContainsTitleField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_TITLE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()
        );
        Matcher<MultiGetResponseItem<?>> documentOneContainsArtistField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_ARTIST,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
        );
        Matcher<MultiGetResponseItem<?>> documentOneContainsLyricsField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_LYRICS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
        );
        Matcher<MultiGetResponseItem<?>> documentOneContainsStarsField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_STARS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
        );
        Matcher<MultiGetResponseItem<?>> documentOneContainsGenreField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_GENRE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
        );
        Matcher<MultiGetResponseItem<?>> documentTwoContainsTitleField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_TITLE,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle()
        );
        Matcher<MultiGetResponseItem<?>> documentTwoContainsArtistField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_ARTIST,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()
        );
        Matcher<MultiGetResponseItem<?>> documentTwoContainsLyricsField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_LYRICS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()
        );
        Matcher<MultiGetResponseItem<?>> documentTwoContainsStarsField = MultiGetResponseItemMatchers.documentContainField(
            FIELD_STARS,
            FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars()
        );
        Matcher<MultiGetResponseItem<?>> documentTwoContainsGenreField = MultiGetResponseItemMatchers.documentContainField(
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
        SearchRequest searchRequest = SearchRequest.of(r -> r.index(FIRST_INDEX_NAME));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ONLY_FIELD_TITLE_FLS)) {
            assertSearchForFLSRestrictions(client, searchRequest, true);
        }

        try (CloseableOpenSearchClient client = cluster.getClient(USER_NO_FIELD_TITLE_FLS)) {
            assertSearchForFLSRestrictions(client, searchRequest, false);
        }
    }

    private void assertSearchForFLSRestrictions(OpenSearchClient client, SearchRequest searchRequest, boolean shouldShowFieldTitle)
        throws IOException, Exception {
        // if shouldShowFieldTitle == true, we check that only the title field is fetched; if shouldShowFieldTitle == false, we check that
        // only the title field is
        // ignored
        SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        GetRequest getRequest = GetRequest.of(r -> r.index(FIRST_INDEX_NAME).id(FIRST_INDEX_ID_SONG_1));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ONLY_FIELD_TITLE_MASKED)) {
            assertProperGetResponsesForTitleFieldMaskingRestriction(client, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingRestriction(OpenSearchClient client, GetRequest getRequest) throws IOException,
        Exception {
        GetResponse<?> getResponse = client.get(getRequest, Map.class);

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
        MgetRequest multiGetRequest = MgetRequest.of(r -> r.index(FIRST_INDEX_NAME).ids(FIRST_INDEX_ID_SONG_1, FIRST_INDEX_ID_SONG_2));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ONLY_FIELD_TITLE_MASKED)) {
            assertProperMultiGetResponseForTitleFieldMaskingRestriction(client, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingRestriction(OpenSearchClient client, MgetRequest multiGetRequest)
        throws IOException, Exception {
        MgetResponse<?> multiGetResponse = client.mget(multiGetRequest, Map.class);
        var getResponses = multiGetResponse.docs();

        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre()
                )
            )
        );
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingRestriction() throws IOException, Exception {
        SearchRequest searchRequest = SearchRequest.of(r -> r.index(FIRST_INDEX_NAME));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ONLY_FIELD_TITLE_MASKED)) {
            assertProperSearchResponseForTitleFieldMaskingRestriction(client, searchRequest);
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingRestriction(OpenSearchClient client, SearchRequest searchRequest)
        throws IOException, Exception {
        SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        GetRequest getRequest = GetRequest.of(r -> r.index(FIRST_INDEX_NAME).id(FIRST_INDEX_ID_SONG_1));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS)) {
            assertProperGetResponsesForOnlyAndNoTitleFLSRestrictions(client, getRequest);
        }
    }

    private void assertProperGetResponsesForOnlyAndNoTitleFLSRestrictions(OpenSearchClient client, GetRequest getRequest)
        throws IOException, Exception {
        GetResponse<?> getResponse = client.get(getRequest, Map.class);

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
        MgetRequest multiGetRequest = MgetRequest.of(r -> r.index(FIRST_INDEX_NAME).ids(FIRST_INDEX_ID_SONG_1, FIRST_INDEX_ID_SONG_2));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS)) {
            assertProperMultiGetResponseForOnlyAndNoTitleFLSRestrictions(client, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForOnlyAndNoTitleFLSRestrictions(OpenSearchClient client, MgetRequest multiGetRequest)
        throws IOException, Exception {
        MgetResponse<?> multiGetResponse = client.mget(multiGetRequest, Map.class);
        var getResponses = multiGetResponse.docs();

        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_TITLE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_TITLE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre()
                )
            )
        );
    }

    @Test
    public void testSearchDocumentWithWithNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = SearchRequest.of(r -> r.index(FIRST_INDEX_NAME));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_ONLY_AND_NO_FIELD_TITLE_FLS)) {
            assertProperSearchResponseForOnlyAndNoTitleFLSRestrictions(client, searchRequest);
        }
    }

    private void assertProperSearchResponseForOnlyAndNoTitleFLSRestrictions(OpenSearchClient client, SearchRequest searchRequest)
        throws IOException, Exception {
        SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        GetRequest getRequest = GetRequest.of(r -> r.index(FIRST_INDEX_NAME).id(FIRST_INDEX_ID_SONG_1));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperGetResponsesForTitleFieldMaskingAndOnlyTitleFLSRestrictions(client, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingAndOnlyTitleFLSRestrictions(OpenSearchClient client, GetRequest getRequest)
        throws IOException, Exception {
        GetResponse<?> getResponse = client.get(getRequest, Map.class);

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
        MgetRequest multiGetRequest = MgetRequest.of(r -> r.index(FIRST_INDEX_NAME).ids(FIRST_INDEX_ID_SONG_1, FIRST_INDEX_ID_SONG_2));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperMultiGetResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(client, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(
        OpenSearchClient client,
        MgetRequest multiGetRequest
    ) throws IOException, Exception {
        MgetResponse<?> multiGetResponse = client.mget(multiGetRequest, Map.class);
        var getResponses = multiGetResponse.docs();

        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_TITLE,
                    VALUE_TO_MASKED_VALUE.apply(FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle())
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_ARTIST,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_ARTIST,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_LYRICS,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_LYRICS,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_STARS,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_STARS,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_GENRE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_GENRE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre()
                    )
                )
            )
        );
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingAndOnlyTitleFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = SearchRequest.of(r -> r.index(FIRST_INDEX_NAME));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_ONLY_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperSearchResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(client, searchRequest);
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingAndOnlyTitleFLSRestrictions(
        OpenSearchClient client,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        GetRequest getRequest = GetRequest.of(r -> r.index(FIRST_INDEX_NAME).id(FIRST_INDEX_ID_SONG_1));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperGetResponsesForTitleFieldMaskingAndNoTitleFLSRestrictions(client, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingAndNoTitleFLSRestrictions(OpenSearchClient client, GetRequest getRequest)
        throws IOException, Exception {
        GetResponse<?> getResponse = client.get(getRequest, Map.class);

        assertThat(getResponse, containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1));
        assertThat(getResponse, not(documentContainField(FIELD_TITLE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle())));
        assertThat(getResponse, documentContainField(FIELD_ARTIST, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()));
        assertThat(getResponse, documentContainField(FIELD_LYRICS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()));
        assertThat(getResponse, documentContainField(FIELD_STARS, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()));
        assertThat(getResponse, documentContainField(FIELD_GENRE, FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()));
    }

    @Test
    public void testMultiGetDocumentWithTitleFieldMaskingAndNoTitleFLSRestrictions() throws IOException, Exception {
        MgetRequest multiGetRequest = MgetRequest.of(r -> r.index(FIRST_INDEX_NAME).ids(FIRST_INDEX_ID_SONG_1, FIRST_INDEX_ID_SONG_2));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(client, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(
        OpenSearchClient client,
        MgetRequest multiGetRequest
    ) throws IOException, Exception {
        MgetResponse<?> multiGetResponse = client.mget(multiGetRequest, Map.class);
        var getResponses = multiGetResponse.docs();

        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_TITLE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_TITLE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre()
                )
            )
        );
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingAndNoTitleFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = SearchRequest.of(r -> r.index(FIRST_INDEX_NAME));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_BOTH_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperSearchResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(client, searchRequest);
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingAndNoTitleFLSRestrictions(
        OpenSearchClient client,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        GetRequest getRequest = GetRequest.of(r -> r.index(FIRST_INDEX_NAME).id(FIRST_INDEX_ID_SONG_1));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperGetResponsesForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(client, getRequest);
        }
    }

    private void assertProperGetResponsesForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
        OpenSearchClient client,
        GetRequest getRequest
    ) throws IOException, Exception {
        GetResponse<?> getResponse = client.get(getRequest, Map.class);

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
        MgetRequest multiGetRequest = MgetRequest.of(r -> r.index(FIRST_INDEX_NAME).ids(FIRST_INDEX_ID_SONG_1, FIRST_INDEX_ID_SONG_2));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(client, multiGetRequest);
        }
    }

    private void assertProperMultiGetResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
        OpenSearchClient client,
        MgetRequest multiGetRequest
    ) throws IOException, Exception {
        MgetResponse<?> multiGetResponse = client.mget(multiGetRequest, Map.class);
        var getResponses = multiGetResponse.docs();

        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_1)));
        assertThat(getResponses, hasItem(MultiGetResponseItemMatchers.containDocument(FIRST_INDEX_NAME, FIRST_INDEX_ID_SONG_2)));

        // since the roles are overlapping, the role with less permissions is the only one that is used- which is no title, and since there
        // is no title the masking role has no effect
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_TITLE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getTitle()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_1).getGenre()
                )
            )
        );
        assertThat(
            getResponses,
            not(
                hasItem(
                    MultiGetResponseItemMatchers.documentContainField(
                        FIELD_TITLE,
                        FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getTitle()
                    )
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_ARTIST,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getArtist()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_LYRICS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getLyrics()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_STARS,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getStars()
                )
            )
        );
        assertThat(
            getResponses,
            hasItem(
                MultiGetResponseItemMatchers.documentContainField(
                    FIELD_GENRE,
                    FIRST_INDEX_SONGS_BY_ID.get(FIRST_INDEX_ID_SONG_2).getGenre()
                )
            )
        );
    }

    @Test
    public void testSearchDocumentWithTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions() throws IOException, Exception {
        SearchRequest searchRequest = SearchRequest.of(r -> r.index(FIRST_INDEX_NAME));

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALL_ONLY_AND_NO_FIELD_TITLE_FLS_ONLY_FIELD_TITLE_MASKED)) {
            assertProperSearchResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(client, searchRequest);
        }
    }

    private void assertProperSearchResponseForTitleFieldMaskingAndNoTitleFieldAndOnlyTitleFieldFLSRestrictions(
        OpenSearchClient client,
        SearchRequest searchRequest
    ) throws IOException, Exception {
        SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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

        try (CloseableOpenSearchClient client = cluster.getClient(USER_FLS_INCLUDE_STARS)) {
            SearchRequest searchRequest = SearchRequest.of(
                r -> r.index(indexName)
                    .storedFields(SizeFieldMapper.NAME, SourceFieldMapper.NAME)
                    .query(org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.matchAll().build().toQuery())
            );
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertSearchHitsDoContainField(searchResponse, FIELD_STARS);
            assertThat(
                searchResponse.hits().hits().stream().map(Hit::metaFields).flatMap(f -> f.keySet().stream()).toList(),
                hasItem(SizeFieldMapper.NAME)
            );
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

        try (CloseableOpenSearchClient client = cluster.getClient(USER_FLS_INCLUDE_STARS)) {
            SearchRequest searchRequest = SearchRequest.of(
                r -> r.index(indexName)
                    .storedFields(SizeFieldMapper.NAME, SourceFieldMapper.NAME)
                    .query(org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.matchAll().build().toQuery())
            );
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertSearchHitsDoContainField(searchResponse, FIELD_STARS);
            assertThat(
                searchResponse.hits().hits().stream().map(Hit::metaFields).flatMap(f -> f.keySet().stream()).toList(),
                hasItem(SizeFieldMapper.NAME)
            );
            assertSearchHitsDoNotContainField(searchResponse, FIELD_ARTIST);
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetMappingsOnAClosedIndexWithFlsRestrictions() throws IOException {
        String indexName = "fls_excludes_mappings";
        List<String> docIds = createIndexWithDocs(indexName, SONGS[0], SONGS[1]);

        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse mappingsResponse = client.get(indexName + "/_mapping");
            mappingsResponse.assertStatusCode(SC_OK);
            assertThat(mappingsResponse.getBody(), containsString("title"));

            TestRestClient.HttpResponse closeResponse = client.post(indexName + "/_close");
            closeResponse.assertStatusCode(SC_OK);
        }

        try (TestRestClient client = cluster.getRestClient(USER_NO_FIELD_TITLE_WILDCARD_INDEX_FLS)) {
            TestRestClient.HttpResponse mappingsResponse = client.get(indexName + "/_mapping");
            mappingsResponse.assertStatusCode(SC_OK);
            assertThat(mappingsResponse.getBody(), not(containsString("title")));
        }
    }

}
