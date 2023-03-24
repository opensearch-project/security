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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.get.*;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.*;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.metrics.ParsedAvg;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.Song.*;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.*;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.*;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.isSuccessfulMultiGetResponse;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.numberOfGetItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.isSuccessfulMultiSearchResponse;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.numberOfSearchItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.*;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DlsIntegrationTests {

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


	static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

	/**
	* User who is allowed to read all indices.
	*/
	static final TestSecurityConfig.User READ_ALL_USER = new TestSecurityConfig.User("read_all_user")
			.roles(
					new TestSecurityConfig.Role("read_all_user")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.on("*")
			);

	/**
	* User who is allowed to see all fields on indices {@link #FIRST_INDEX_NAME} and {@link #SECOND_INDEX_NAME}.
	*/
	static final TestSecurityConfig.User READ_FIRST_AND_SECOND_USER = new TestSecurityConfig.User("read_first_and_second_user")
			.roles(
					new TestSecurityConfig.Role("first_index_reader")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.on(FIRST_INDEX_NAME),
					new TestSecurityConfig.Role("second_index_reader")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.on(SECOND_INDEX_NAME)
			);

	/**
	* User who is allowed to see documents on all indices where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_STRING}.
	*/
	static final TestSecurityConfig.User READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_STRING = new TestSecurityConfig.User("read_where_field_artist_matches_artist_string")
			.roles(
					new TestSecurityConfig.Role("read_where_field_artist_matches_artist_string")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_STRING))
							.on("*")
			);

	/**
	 * User who is allowed to see documents on all indices where value of the {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_TWINS} OR {@link Song#FIELD_STARS} is greater than zero.
	 */
	static final TestSecurityConfig.User READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_ZERO = new TestSecurityConfig.User("read_where_field_artist_matches_artist_twins_or_field_stars_greater_than_zero")
			.roles(
					new TestSecurityConfig.Role("read_where_field_artist_matches_artist_twins")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_TWINS))
							.on("*"),
					new TestSecurityConfig.Role("read_where_field_stars_greater_than_zero")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.dls(String.format("{\"range\":{\"%s\":{\"gt\":%d}}}", FIELD_STARS, 0))
							.on("*")
			);


	/**
	* User who is allowed to see documents on indices where value of {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_TWINS} or {@link Song#FIELD_ARTIST} field matches {@link Song#ARTIST_FIRST}:
	*/
	static final TestSecurityConfig.User READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST = new TestSecurityConfig.User("read_where_field_artist_matches_artist_twins_or_artist_first")
			.roles(
					new TestSecurityConfig.Role("read_where_field_artist_matches_artist_twins")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_TWINS))
							.on(FIRST_INDEX_NAME),
					new TestSecurityConfig.Role("read_where_field_artist_matches_artist_first")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_ARTIST, ARTIST_FIRST))
							.on(SECOND_INDEX_NAME)
			);

	/**
	* User who is allowed to see documents on all indices where value of the {@link Song#FIELD_STARS} is less than zero.
	*/
	static final TestSecurityConfig.User READ_WHERE_STARS_LESS_THAN_ZERO = new TestSecurityConfig.User("read_where_stars_less_than_zero")
			.roles(
					new TestSecurityConfig.Role("read_where_stars_less_than_zero")
							.clusterPermissions("cluster_composite_ops_ro")
							.indexPermissions("read")
							.dls(String.format("{\"range\":{\"%s\":{\"lt\":%d}}}", FIELD_STARS, 0))
							.on("*")
			);

	@ClassRule
	public static final LocalCluster cluster = new LocalCluster.Builder()
			.clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS).anonymousAuth(false)
			.nodeSettings(Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName()  +"__" + ALL_ACCESS.getName())))
			.authc(AUTHC_HTTPBASIC_INTERNAL)
			.users(
					ADMIN_USER, READ_ALL_USER, READ_FIRST_AND_SECOND_USER, READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_STRING,
					READ_WHERE_STARS_LESS_THAN_ZERO, READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_ZERO,
					READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST
			)
			.build();

	/**
	* Function that returns id assigned to song with title equal to given title or throws {@link RuntimeException}
	* when no song matches.
	*/
	static final BiFunction<Map<String, Song>, String, String> FIND_ID_OF_SONG_WITH_TITLE = (map, title) -> map.entrySet()
			.stream().filter(entry -> title.equals(entry.getValue().getTitle()))
			.findAny()
			.map(Map.Entry::getKey)
			.orElseThrow(() -> new RuntimeException("Cannot find id of song with title: " + title));

	/**
	* Function that returns id assigned to song with artist equal to given artist or throws {@link RuntimeException}
	* when no song matches.
	*/
	static final BiFunction<Map<String, Song>, String, String> FIND_ID_OF_SONG_WITH_ARTIST = (map, artist) -> map.entrySet()
			.stream().filter(entry -> artist.equals(entry.getValue().getArtist()))
			.findAny()
			.map(Map.Entry::getKey)
			.orElseThrow(() -> new RuntimeException("Cannot find id of song with artist: " + artist));

	static final TreeMap<String, Song> FIRST_INDEX_SONGS_BY_ID = new TreeMap<>() {{
		put(FIRST_INDEX_ID_SONG_1, SONGS[0]);
		put(FIRST_INDEX_ID_SONG_2, SONGS[1]);
		put(FIRST_INDEX_ID_SONG_3, SONGS[2]);
		put(FIRST_INDEX_ID_SONG_4, SONGS[3]);
	}};

	static final TreeMap<String, Song> SECOND_INDEX_SONGS_BY_ID = new TreeMap<>() {{
		put(SECOND_INDEX_ID_SONG_1, SONGS[3]);
		put(SECOND_INDEX_ID_SONG_2, SONGS[2]);
		put(SECOND_INDEX_ID_SONG_3, SONGS[1]);
		put(SECOND_INDEX_ID_SONG_4, SONGS[0]);
	}};

	@BeforeClass
	public static void createTestData() {
		try(Client client = cluster.getInternalNodeClient()){
			FIRST_INDEX_SONGS_BY_ID.forEach((id, song) -> {
				client.prepareIndex(FIRST_INDEX_NAME).setId(id).setRefreshPolicy(IMMEDIATE).setSource(song.asMap()).get();
			});

			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
					.indices(FIRST_INDEX_NAME)
					.alias(FIRST_INDEX_ALIAS)
			)).actionGet();
			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
					.index(FIRST_INDEX_NAME)
					.alias(FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE)
					.filter(QueryBuilders.queryStringQuery(QUERY_TITLE_NEXT_SONG))
			)).actionGet();
			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
					.index(FIRST_INDEX_NAME)
					.alias(FIRST_INDEX_ALIAS_FILTERED_BY_TWINS_ARTIST)
					.filter(QueryBuilders.queryStringQuery(String.format("%s:%s", FIELD_ARTIST, ARTIST_TWINS)))
			)).actionGet();
			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
					.index(FIRST_INDEX_NAME)
					.alias(FIRST_INDEX_ALIAS_FILTERED_BY_FIRST_ARTIST)
					.filter(QueryBuilders.queryStringQuery(String.format("%s:%s", FIELD_ARTIST, ARTIST_FIRST)))
			)).actionGet();

			SECOND_INDEX_SONGS_BY_ID.forEach((id, song) -> {
				client.prepareIndex(SECOND_INDEX_NAME).setId(id).setRefreshPolicy(IMMEDIATE).setSource(song.asMap()).get();
			});
			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new IndicesAliasesRequest.AliasActions(ADD)
					.indices(SECOND_INDEX_NAME)
					.alias(SECOND_INDEX_ALIAS)
			)).actionGet();
		}
	}

	@Test
	public void searchForDocuments() throws IOException {

		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_ALL_USER)) {
			SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));

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
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));

			searchRequest = new SearchRequest(SECOND_INDEX_NAME);
			searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_NO));
		}
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_STRING)) {
			SearchRequest searchRequest = new SearchRequest(ALL_INDICES_ALIAS);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_STRING));
			assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));
		}
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_STRING)) {
			SearchRequest searchRequest = new SearchRequest(ALL_INDICES_ALIAS);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(2));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_STRING));
			assertThat(searchResponse, searchHitContainsFieldWithValue(1, FIELD_ARTIST, ARTIST_STRING));
		}
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST)) {
			SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_NAME);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));

			searchRequest = new SearchRequest(SECOND_INDEX_NAME);
			searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
		}
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_STARS_LESS_THAN_ZERO)) {
			String aggregationName = "averageStars";
			SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
			Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
			assertThat(actualAggregation, instanceOf(ParsedAvg.class));
			assertThat(((ParsedAvg) actualAggregation).getValue(), is(Double.POSITIVE_INFINITY));
		}
	}

	@Test
	public void searchForDocumentsWithIndexPattern() throws IOException {


		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST)) {
			SearchRequest searchRequest = new SearchRequest("*".concat(FIRST_INDEX_NAME));
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));

			searchRequest = new SearchRequest("*".concat(SECOND_INDEX_NAME));
			searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_NO));
		}
	}

	@Test
	public void searchForDocumentsViaAlias() throws IOException {

		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_FIRST_AND_SECOND_USER)) {
			SearchRequest searchRequest = new SearchRequest(FIRST_INDEX_ALIAS);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));

			searchRequest = new SearchRequest(SECOND_INDEX_ALIAS);
			searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(4));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_NO));
		}
	}


	@Test
	public void scrollOverSearchResults() throws IOException {

		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST)) {
			SearchRequest searchRequest = searchRequestWithScroll(FIRST_INDEX_NAME, 2);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containNotEmptyScrollingId());

			SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

			SearchResponse scrollResponse = restHighLevelClient.scroll(scrollRequest, DEFAULT);
			assertThat(scrollResponse, isSuccessfulSearchResponse());
			assertThat(scrollResponse, containNotEmptyScrollingId());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
		}
	}

	@Test
	public void aggregateDataAndComputeAverage() throws IOException {

		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST)) {
			String aggregationName = "averageStars";
			Song song = FIRST_INDEX_SONGS_BY_ID.get(FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_TWINS));

			SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
			Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
			assertThat(actualAggregation, instanceOf(ParsedAvg.class));
			assertThat(((ParsedAvg) actualAggregation).getValue(), is(song.getStars()*1.0));
		}
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_ZERO)) {
			String aggregationName = "averageStars";
			SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
			Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
			assertThat(actualAggregation, instanceOf(ParsedAvg.class));
			assertThat(((ParsedAvg) actualAggregation).getValue(), is(2.5));
		}
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_FIELD_STARS_GREATER_THAN_ZERO)) {
			String aggregationName = "averageStars";
			SearchRequest searchRequest = averageAggregationRequest(FIRST_INDEX_NAME, aggregationName, FIELD_STARS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
			Aggregation actualAggregation = searchResponse.getAggregations().get(aggregationName);
			assertThat(actualAggregation, instanceOf(ParsedAvg.class));
			assertThat(((ParsedAvg) actualAggregation).getValue(), is(2.5));
		}
	}

	@Test
	public void getDocument() throws IOException {

		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST)) {
			String songId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_TWINS);

			GetResponse response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, songId), DEFAULT);

			assertThat(response, containDocument(FIRST_INDEX_NAME, songId));

			songId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_STRING);

			response = restHighLevelClient.get(new GetRequest(FIRST_INDEX_NAME, songId), DEFAULT);

			assertThat(response, not(containDocument(FIRST_INDEX_NAME, songId)));
		}
	}

	@Test
	public void multiGetDocuments() throws IOException {

		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST)) {
			List<String> indicesToCheck = List.of(FIRST_INDEX_NAME, FIRST_INDEX_ALIAS);
			String firstSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_NO);
			String secondSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_STRING);

			for(String index : indicesToCheck) {
				MultiGetRequest request = new MultiGetRequest();
				request.add(new MultiGetRequest.Item(index, firstSongId));
				request.add(new MultiGetRequest.Item(index, secondSongId));

				MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

				assertThat(response, isSuccessfulMultiGetResponse());
				assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

				MultiGetItemResponse[] responses = response.getResponses();
				assertThat(responses[0].getResponse(), allOf(
						not(containDocument(FIRST_INDEX_NAME, firstSongId)))
				);
				assertThat(responses[1].getResponse(), allOf(
						not(containDocument(FIRST_INDEX_NAME, secondSongId)))
				);
			}
		}
	}

	@Test
	public void multiSearchDocuments() throws IOException {

		//DLS
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(READ_WHERE_FIELD_ARTIST_MATCHES_ARTIST_TWINS_OR_MATCHES_ARTIST_FIRST)) {
			List<List<String>> indicesToCheck = List.of(
					List.of(FIRST_INDEX_NAME, SECOND_INDEX_NAME),
					List.of(FIRST_INDEX_ALIAS, SECOND_INDEX_ALIAS)
			);
			String firstSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(FIRST_INDEX_SONGS_BY_ID, ARTIST_TWINS);
			String secondSongId = FIND_ID_OF_SONG_WITH_ARTIST.apply(SECOND_INDEX_SONGS_BY_ID, ARTIST_FIRST);

			for (List<String> indices : indicesToCheck) {
				MultiSearchRequest request = new MultiSearchRequest();
				indices.forEach(index -> request.add(new SearchRequest(index)));

				MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

				assertThat(response, isSuccessfulMultiSearchResponse());
				assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

				MultiSearchResponse.Item[] responses = response.getResponses();

				assertThat(responses[0].getResponse(), searchHitsContainDocumentWithId(0, FIRST_INDEX_NAME, firstSongId));
				assertThat(responses[0].getResponse(), searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_TWINS));
				assertThat(responses[1].getResponse(), searchHitsContainDocumentWithId(0, SECOND_INDEX_NAME, secondSongId));
				assertThat(responses[1].getResponse(), searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
			}

		}
	}
}
