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
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.metrics.ParsedAvg;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.ARTIST_FIRST;
import static org.opensearch.security.Song.ARTIST_NO;
import static org.opensearch.security.Song.ARTIST_STRING;
import static org.opensearch.security.Song.ARTIST_TWINS;
import static org.opensearch.security.Song.ARTIST_UNKNOWN;
import static org.opensearch.security.Song.ARTIST_YES;
import static org.opensearch.security.Song.FIELD_ARTIST;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.opensearch.security.Song.QUERY_TITLE_NEXT_SONG;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentsInAnyOrder;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DlsIntegrationTests {

    static final String FIRST_INDEX_ID_SONG_1 = "INDEX_1_S1";
    static final String FIRST_INDEX_ID_SONG_2 = "INDEX_1_S2";
    static final String FIRST_INDEX_ID_SONG_3 = "INDEX_1_S3";
    static final String FIRST_INDEX_ID_SONG_4 = "INDEX_1_S4";
    static final String FIRST_INDEX_ID_SONG_5 = "INDEX_1_S5";
    static final String FIRST_INDEX_ID_SONG_6 = "INDEX_1_S6";
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
    static final String UNION_TEST_INDEX_NAME = "my_index1";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    /**
    * User who is allowed to read all indices.
    */
    static final TestSecurityConfig.User READ_ALL_USER = new TestSecurityConfig.User("read_all_user").roles(
        new TestSecurityConfig.Role("read_all_user").clusterPermissions("cluster_composite_ops_ro").indexPermissions("read").on("*")
    );

    /**
    * User who is allowed to see all fields on indices {@link #FIRST_INDEX_NAME} and {@link #SECOND_INDEX_NAME}.
    */
    static final TestSecurityConfig.User READ_FIRST_AND_SECOND_USER = new TestSecurityConfig.User("read_first_and_second_user").roles(
        new TestSecurityConfig.Role("first_index_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .on(FIRST_INDEX_NAME),
        new TestSecurityConfig.Role("second_index_reader").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .on(SECOND_INDEX_NAME)
    );

    /**
    * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_STRING}.
    */
    static final TestSecurityConfig.User READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_STRING = new TestSecurityConfig.User(
        "read_where_field_artist_matches_artist_string"
    ).roles(
        new TestSecurityConfig.Role("read_where_field_artist_matches_artist_string").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_STRING))
            .on("*")
    );

    /**
     * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_TWINS} OR {@link Song#FIELD_STARS} is greater than five.
     */
    static final TestSecurityConfig.User READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_FIVE =
        new TestSecurityConfig.User("read_where_field_artist_matches_artist_twins_or_field_stars_greater_than_five").roles(
            new TestSecurityConfig.Role("read_where_field_artist_matches_artist_twins").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_TWINS))
                .on("*"),
            new TestSecurityConfig.Role("read_where_field_stars_greater_than_five").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls(String.format("{\"range\":{\"%s\":{\"gt\":%d}}}", FIELD_STARS, 5))
                .on("*")
        );

    /**
    * User who is allowed to see documents on indices where value of {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_TWINS} or {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_FIRST}:
    */
    static final TestSecurityConfig.User READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST = new TestSecurityConfig.User(
        "read_where_field_artist_matches_artist_twins_or_artist_first"
    ).roles(
        new TestSecurityConfig.Role("read_where_field_artist_matches_artist_twins").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_TWINS))
            .on(FIRST_INDEX_NAME),
        new TestSecurityConfig.Role("read_where_field_artist_matches_artist_first").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_FIRST))
            .on(SECOND_INDEX_NAME)
    );

    /**
    * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_STARS} is less than three.
    */
    static final TestSecurityConfig.User READ_WHERE_STARS_LESS_THAN_THREE = new TestSecurityConfig.User("read_where_stars_less_than_three")
        .roles(
            new TestSecurityConfig.Role("read_where_stars_less_than_three").clusterPermissions("cluster_composite_ops_ro")
                .indexPermissions("read")
                .dls(String.format("{\"range\":{\"%s\":{\"lt\":%d}}}", FIELD_STARS, 3))
                .on("*")
        );

    /**
     * Test role 1 for DLS filtering with two (non)overlapping roles. This role imposes a filter where the user can only access documents where the sensitive field is false. This role is applied at a higher level for all index patterns.
     */
    static final TestSecurityConfig.Role ROLE_NON_SENSITIVE_ONLY = new TestSecurityConfig.Role("test_role_1").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").dls("{\"match\":{\"sensitive\":false}}").on("*");

    /**
     * Test role 2 for DLS filtering with two overlapping roles. This role does not impose any filter, and combined with TEST_ROLE_ONE should yield a union that does not impose any filter. This role is applied at a lower level for index patterns my_index*.
     */
    static final TestSecurityConfig.Role ROLE_ALLOW_ALL = new TestSecurityConfig.Role("test_role_2").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").dls("{\"match_all\": {}}").on("my_index*");

    /**
     * Test role 3 for DLS filtering with two nonoverlapping roles. This role imposes a filter where the user can only access documents where the genre field is History, and combined with TEST_ROLE_ONE should yield a union that allows the user to access every document except the one with genre Science and sensitive true. This role is applied at a lower level for index patterns my_index*.
     */
    static final TestSecurityConfig.Role ROLE_MATCH_HISTORY_GENRE_ONLY = new TestSecurityConfig.Role("test_role_3").clusterPermissions(
        "cluster_composite_ops_ro"
    ).indexPermissions("read").dls("{\"match\":{\"genre\":\"History\"}}").on("my_index*");

    /**
     * User with DLS permission to only be able to access documents with false sensitive property.
     */
    static final TestSecurityConfig.User USER_NON_SENSITIVE_ONLY = new TestSecurityConfig.User("test_role_1_user").roles(
        ROLE_NON_SENSITIVE_ONLY
    );

    /**
     * User with DLS permission to access all documents.
     */
    static final TestSecurityConfig.User USER_ALLOW_ALL = new TestSecurityConfig.User("test_role_2_user").roles(ROLE_ALLOW_ALL);

    /**
     * User with DLS permission to access documents with genre property matching History.
     */
    static final TestSecurityConfig.User USER_MATCH_HISTORY_GENRE_ONLY = new TestSecurityConfig.User("test_role_3_user").roles(
        ROLE_MATCH_HISTORY_GENRE_ONLY
    );

    /**
     * User with overlapping DLS permissions to access documents with false sensitive property and access all documents- should yield accessing all documents.
     */
    static final TestSecurityConfig.User USER_UNION_OF_OVERLAPPING_ROLES_NON_SENSITIVE_ONLY_AND_ALLOW_ALL = new TestSecurityConfig.User(
        "test_union_of_overlapping_roles_user"
    ).roles(ROLE_NON_SENSITIVE_ONLY, ROLE_ALLOW_ALL);

    /**
     * User with non-overlapping DLS permissions to access documents with false sensitive property and genre property matching History.
     */
    static final TestSecurityConfig.User USER_UNION_OF_NONOVERLAPPING_ROLES_NON_SENSITIVE_ONLY_AND_HISTORY_GENRE_ONLY =
        new TestSecurityConfig.User("test_union_of_non_overlapping_roles_user").roles(
            ROLE_NON_SENSITIVE_ONLY,
            ROLE_MATCH_HISTORY_GENRE_ONLY
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
            READ_ALL_USER,
            READ_FIRST_AND_SECOND_USER,
            READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_STRING,
            READ_WHERE_STARS_LESS_THAN_THREE,
            READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_FIVE,
            READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST,
            USER_NON_SENSITIVE_ONLY,
            USER_ALLOW_ALL,
            USER_MATCH_HISTORY_GENRE_ONLY,
            USER_UNION_OF_OVERLAPPING_ROLES_NON_SENSITIVE_ONLY_AND_ALLOW_ALL,
            USER_UNION_OF_NONOVERLAPPING_ROLES_NON_SENSITIVE_ONLY_AND_HISTORY_GENRE_ONLY
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
        { // SONG = (String artist, String title, String lyrics, Integer stars, String genre)
            put(FIRST_INDEX_ID_SONG_1, SONGS[0]); // (ARTIST_FIRST, TITLE_MAGNUM_OPUS ,LYRICS_1, 1, GENRE_ROCK)
            put(FIRST_INDEX_ID_SONG_2, SONGS[1]); // (ARTIST_STRING, TITLE_SONG_1_PLUS_1, LYRICS_2, 2, GENRE_BLUES),
            put(FIRST_INDEX_ID_SONG_3, SONGS[2]); // (ARTIST_TWINS, TITLE_NEXT_SONG, LYRICS_3, 3, GENRE_JAZZ),
            put(FIRST_INDEX_ID_SONG_4, SONGS[3]); // (ARTIST_NO, TITLE_POISON, LYRICS_4, 4, GENRE_ROCK),
            put(FIRST_INDEX_ID_SONG_5, SONGS[4]); // (ARTIST_YES, TITLE_AFFIRMATIVE,LYRICS_5, 5, GENRE_BLUES),
            put(FIRST_INDEX_ID_SONG_6, SONGS[5]); // (ARTIST_UNKNOWN, TITLE_CONFIDENTIAL, LYRICS_6, 6, GENRE_JAZZ)
        }
    };

    static final TreeMap<String, Song> SECOND_INDEX_SONGS_BY_ID = new TreeMap<>() {
        {
            put(SECOND_INDEX_ID_SONG_1, SONGS[3]); // (ARTIST_NO, TITLE_POISON, LYRICS_4, 4, GENRE_ROCK),
            put(SECOND_INDEX_ID_SONG_2, SONGS[2]); // (ARTIST_TWINS, TITLE_NEXT_SONG, LYRICS_3, 3, GENRE_JAZZ),
            put(SECOND_INDEX_ID_SONG_3, SONGS[1]); // (ARTIST_STRING, TITLE_SONG_1_PLUS_1, LYRICS_2, 2, GENRE_BLUES),
            put(SECOND_INDEX_ID_SONG_4, SONGS[0]); // (ARTIST_FIRST, TITLE_MAGNUM_OPUS ,LYRICS_1, 1, GENRE_ROCK)
        }
    };

    static final TreeMap<String, Map<String, Serializable>> UNION_ROLE_TEST_DATA = new TreeMap<>() {
        {
            put("1", Map.of("genre", "History", "date", "01-01-2020", "sensitive", true));
            put("2", Map.of("genre", "History", "date", "01-01-2020", "sensitive", true));
            put("3", Map.of("genre", "History", "date", "01-01-2020", "sensitive", true));
            put("4", Map.of("genre", "History", "date", "01-01-2020", "sensitive", true));
            put("5", Map.of("genre", "History", "date", "01-01-2020", "sensitive", true));
            put("6", Map.of("genre", "Math", "date", "01-01-2020", "sensitive", false));
            put("7", Map.of("genre", "Math", "date", "01-01-2020", "sensitive", false));
            put("8", Map.of("genre", "Math", "date", "01-01-2020", "sensitive", false));
            put("9", Map.of("genre", "Math", "date", "01-01-2020", "sensitive", false));
            put("10", Map.of("genre", "Science", "date", "01-01-2020", "sensitive", true));
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

            UNION_ROLE_TEST_DATA.forEach((index, document) -> {
                client.prepareIndex(UNION_TEST_INDEX_NAME).setId(index).setRefreshPolicy(IMMEDIATE).setSource(document).get();
            });
        }
    }

    @Test
    public void testShouldSearchAll() throws IOException {

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_ALL_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(6));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));
            assertThat(searchResponse, searchHitContainsFieldWithValue(2, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(searchResponse, searchHitContainsFieldWithValue(3, FIELD_ARTIST, ARTIST_NO));
            assertThat(searchResponse, searchHitContainsFieldWithValue(4, FIELD_ARTIST, ARTIST_YES));
            assertThat(searchResponse, searchHitContainsFieldWithValue(5, FIELD_ARTIST, ARTIST_UNKNOWN));

            searchRequest = new SearchRequest(SECOND_INDEX_NAME);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_NO));
        }
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_FIRST_AND_SECOND_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(6));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));
            assertThat(searchResponse, searchHitContainsFieldWithValue(2, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(searchResponse, searchHitContainsFieldWithValue(3, FIELD_ARTIST, ARTIST_NO));
            assertThat(searchResponse, searchHitContainsFieldWithValue(4, FIELD_ARTIST, ARTIST_YES));
            assertThat(searchResponse, searchHitContainsFieldWithValue(5, FIELD_ARTIST, ARTIST_UNKNOWN));

            searchRequest = new SearchRequest(SECOND_INDEX_NAME);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_NO));
        }
    }

    @Test
    public void testShouldSearchI1_S2I2_S3() throws IOException {

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_STRING)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_STRING));

            searchRequest = new SearchRequest(SECOND_INDEX_NAME);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_STRING));
        }
    }

    public void testShouldSearchI1_S3I1_S6I2_S2() throws IOException {

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_FIVE
            )
        ) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_UNKNOWN));

            searchRequest = new SearchRequest(SECOND_INDEX_NAME);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
        }
    }

    public void testShouldSearchI1_S1I1_S3I2_S2I2_S4() throws IOException {

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST
            )
        ) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_FIRST));

            searchRequest = new SearchRequest(SECOND_INDEX_NAME);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_FIRST));
        }
    }

    public void testShouldSearchStarsLessThanThree() throws IOException {

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_STARS_LESS_THAN_THREE)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));

            searchRequest = new SearchRequest(SECOND_INDEX_NAME);
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_STRING));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_FIRST));
        }
    }

    @Test
    public void testSearchForAllDocumentsWithIndexPattern() throws IOException {

        // DLS
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_ALL_USER)) {
            SearchRequest searchRequest = new SearchRequest("*".concat(FIRST_INDEX_NAME));
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(6));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));
            assertThat(searchResponse, searchHitContainsFieldWithValue(2, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(searchResponse, searchHitContainsFieldWithValue(3, FIELD_ARTIST, ARTIST_NO));
            assertThat(searchResponse, searchHitContainsFieldWithValue(4, FIELD_ARTIST, ARTIST_YES));
            assertThat(searchResponse, searchHitContainsFieldWithValue(5, FIELD_ARTIST, ARTIST_UNKNOWN));

            searchRequest = new SearchRequest("*".concat(SECOND_INDEX_NAME));
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_NO));
        }
    }

    @Test
    public void testSearchForAllDocumentsWithAlias() throws IOException {

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_ALL_USER)) {
            SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(6));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
            assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));
            assertThat(searchResponse, searchHitContainsFieldWithValue(2, FIELD_ARTIST, ARTIST_TWINS));
            assertThat(searchResponse, searchHitContainsFieldWithValue(3, FIELD_ARTIST, ARTIST_NO));
            assertThat(searchResponse, searchHitContainsFieldWithValue(4, FIELD_ARTIST, ARTIST_YES));
            assertThat(searchResponse, searchHitContainsFieldWithValue(5, FIELD_ARTIST, ARTIST_UNKNOWN));

            searchRequest = new SearchRequest("*".concat(SECOND_INDEX_NAME));
            searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
            assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_NO));
        }
    }

    @Test
    public void testAggregateAndComputeStarRatings() throws IOException {

        // DLS
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST
            )
        ) {
            String aggregationName = "averageStars";
            Song song = FIRST_INDEX_SONGS_BY_ID.get(FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_TWINS));

            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(song.getStars() * 1.0));
        }
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_FIVE
            )
        ) {
            String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(4.5));
        }
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_STARS_LESS_THAN_THREE)) {
            String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
            Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
            assertThat(actualAggregation, instanceOf(ParsedAvg.class));
            assertThat(((ParsedAvg) actualAggregation).getValue(), is(1.5));
        }
    }

    @Test
    public void testOverlappingRoleUnionSearchFiltering() throws Exception {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_NON_SENSITIVE_ONLY)) {
            SearchRequest searchRequest = new SearchRequest(UNION_TEST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchResponseHitsEqualTo(searchResponse, 4);

            assertThat(
                searchResponse,
                searchHitsContainDocumentsInAnyOrder(
                    UNION_ROLE_TEST_DATA.entrySet()
                        .stream()
                        .filter(e -> e.getValue().get("sensitive").equals(false))
                        .map(e -> Pair.of(UNION_TEST_INDEX_NAME, e.getKey()))
                        .collect(Collectors.toList())
                )
            );
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ALLOW_ALL)) {
            SearchRequest searchRequest = new SearchRequest(UNION_TEST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchResponseHitsEqualTo(searchResponse, 10);
        }

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_UNION_OF_OVERLAPPING_ROLES_NON_SENSITIVE_ONLY_AND_ALLOW_ALL
            )
        ) {
            SearchRequest searchRequest = new SearchRequest(UNION_TEST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchResponseHitsEqualTo(searchResponse, 10);

            // shows that roles are additive and the overlapping role with less filtering is used
            assertThat(
                searchResponse,
                searchHitsContainDocumentsInAnyOrder(
                    UNION_ROLE_TEST_DATA.keySet().stream().map(id -> Pair.of(UNION_TEST_INDEX_NAME, id)).collect(Collectors.toList())
                )
            );
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testNonOverlappingRoleUnionSearchFiltering() throws Exception {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_NON_SENSITIVE_ONLY)) {
            SearchRequest searchRequest = new SearchRequest(UNION_TEST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchResponseHitsEqualTo(searchResponse, 4);

            assertThat(
                searchResponse,
                searchHitsContainDocumentsInAnyOrder(
                    UNION_ROLE_TEST_DATA.entrySet()
                        .stream()
                        .filter(e -> e.getValue().get("sensitive").equals(false))
                        .map(e -> Pair.of(UNION_TEST_INDEX_NAME, e.getKey()))
                        .collect(Collectors.toList())
                )
            );
        }

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_MATCH_HISTORY_GENRE_ONLY)) {
            SearchRequest searchRequest = new SearchRequest(UNION_TEST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchResponseHitsEqualTo(searchResponse, 5);

            assertThat(
                searchResponse,
                searchHitsContainDocumentsInAnyOrder(
                    UNION_ROLE_TEST_DATA.entrySet()
                        .stream()
                        .filter(e -> e.getValue().get("genre").equals("History"))
                        .map(e -> Pair.of(UNION_TEST_INDEX_NAME, e.getKey()))
                        .collect(Collectors.toList())
                )
            );
        }

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_UNION_OF_NONOVERLAPPING_ROLES_NON_SENSITIVE_ONLY_AND_HISTORY_GENRE_ONLY
            )
        ) {
            SearchRequest searchRequest = new SearchRequest(UNION_TEST_INDEX_NAME);
            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

            assertSearchResponseHitsEqualTo(searchResponse, 9);

            assertThat(
                searchResponse,
                searchHitsContainDocumentsInAnyOrder(
                    UNION_ROLE_TEST_DATA.keySet()
                        .stream()
                        .filter(id -> !id.equals("10"))
                        .map(id -> Pair.of(UNION_TEST_INDEX_NAME, id))
                        .collect(Collectors.toList())
                )
            );

            // shows that the roles are additive, but excludes one document since the DLS filters for both roles do not account for this
            assertThat(searchResponse, not(searchHitsContainDocumentsInAnyOrder(Pair.of(UNION_TEST_INDEX_NAME, "10"))));
        }
    }

    private void assertSearchResponseHitsEqualTo(SearchResponse searchResponse, int hits) throws Exception {
        assertThat(searchResponse, isSuccessfulSearchResponse());
        assertThat(searchResponse, numberOfTotalHitsIsEqualTo(hits));
    }
}
