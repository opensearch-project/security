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
import java.util.concurrent.ExecutionException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.base.Stopwatch;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.awaitility.Awaitility;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.cluster.repositories.delete.DeleteRepositoryRequest;
import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotResponse;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.template.delete.DeleteIndexTemplateRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesRequest;
import org.opensearch.action.fieldcaps.FieldCapabilitiesResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetRequest.Item;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchScrollRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.client.ClusterAdminClient;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.core.CountRequest;
import org.opensearch.client.indices.PutIndexTemplateRequest;
import org.opensearch.cluster.metadata.IndexTemplateMetadata;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ReindexRequest;
import org.opensearch.repositories.RepositoryMissingException;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.REMOVE;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.rest.RestStatus.ACCEPTED;
import static org.opensearch.rest.RestStatus.FORBIDDEN;
import static org.opensearch.rest.RestStatus.INTERNAL_SERVER_ERROR;
import static org.opensearch.security.Song.FIELD_ARTIST;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.opensearch.security.Song.FIELD_TITLE;
import static org.opensearch.security.Song.QUERY_TITLE_MAGNUM_OPUS;
import static org.opensearch.security.Song.QUERY_TITLE_NEXT_SONG;
import static org.opensearch.security.Song.QUERY_TITLE_POISON;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.Song.TITLE_MAGNUM_OPUS;
import static org.opensearch.security.Song.TITLE_NEXT_SONG;
import static org.opensearch.security.Song.TITLE_POISON;
import static org.opensearch.security.Song.TITLE_SONG_1_PLUS_1;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.statsAggregationRequest;
import static org.opensearch.test.framework.matcher.BulkResponseMatchers.bulkResponseContainExceptions;
import static org.opensearch.test.framework.matcher.BulkResponseMatchers.failureBulkResponse;
import static org.opensearch.test.framework.matcher.BulkResponseMatchers.successBulkResponse;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainSuccessSnapshot;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainTemplate;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainTemplateWithAlias;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainsDocument;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainsDocumentWithFieldValue;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainsSnapshotRepository;
import static org.opensearch.test.framework.matcher.ClusterMatchers.snapshotInClusterDoesNotExists;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containDocument;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.errorMessageContain;
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
public class SearchOperationTest {

	private static final Logger log = LogManager.getLogger(SearchOperationTest.class);

	public static final String SONG_INDEX_NAME = "song_lyrics";
	public static final String PROHIBITED_SONG_INDEX_NAME = "prohibited_song_lyrics";
	public static final String WRITE_SONG_INDEX_NAME = "write_song_index";

	public static final String SONG_LYRICS_ALIAS = "song_lyrics_index_alias";
	public static final String PROHIBITED_SONG_ALIAS = "prohibited_song_lyrics_index_alias";
	private static final String COLLECTIVE_INDEX_ALIAS = "collective-index-alias";
	private static final String TEMPLATE_INDEX_PREFIX = "song-transcription*";
	public static final String TEMPORARY_ALIAS_NAME = "temporary-alias";
	public static final String ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001 = "alias-used-in-musical-index-template-0001";
	public static final String ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002 = "alias-used-in-musical-index-template-0002";
	public static final String ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003 = "alias-used-in-musical-index-template-0003";
	public static final String INDEX_NAME_SONG_TRANSCRIPTION_JAZZ = "song-transcription-jazz";

	public static final String MUSICAL_INDEX_TEMPLATE = "musical-index-template";

	public static final String UNDELETABLE_TEMPLATE_NAME = "undeletable-template-name";

	public static final String ALIAS_FROM_UNDELETABLE_TEMPLATE = "alias-from-undeletable-template";

	public static final String TEST_SNAPSHOT_REPOSITORY_NAME = "test-snapshot-repository";

	public static final String UNUSED_SNAPSHOT_REPOSITORY_NAME = "unused-snapshot-repository";

	public static final String RESTORED_SONG_INDEX_NAME = "restored_" + WRITE_SONG_INDEX_NAME;

	public static final String ID_P4 = "4";
	public static final String ID_S3 = "3";
	public static final String ID_S2 = "2";
	public static final String ID_S1 = "1";

	static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

	/**
	* All user read permissions are related to {@link #SONG_INDEX_NAME} index
	*/
	static final User LIMITED_READ_USER = new User("limited_read_user")
		.roles(new Role("limited-song-reader")
			.clusterPermissions("indices:data/read/mget", "indices:data/read/msearch", "indices:data/read/scroll")
			.indexPermissions("indices:data/read/search", "indices:data/read/get", "indices:data/read/mget*", "indices:admin/aliases", "indices:data/read/field_caps", "indices:data/read/field_caps*")
			.on(SONG_INDEX_NAME));

	static final User LIMITED_WRITE_USER = new User("limited_write_user")
		.roles(new Role("limited-write-role")
			.clusterPermissions("indices:data/write/bulk", "indices:admin/template/put", "indices:admin/template/delete", "cluster:admin/repository/put", "cluster:admin/repository/delete", "cluster:admin/snapshot/create", "cluster:admin/snapshot/status", "cluster:admin/snapshot/status[nodes]", "cluster:admin/snapshot/delete", "cluster:admin/snapshot/get", "cluster:admin/snapshot/restore")
			.indexPermissions("indices:data/write/index", "indices:data/write/bulk[s]", "indices:admin/create", "indices:admin/mapping/put",
			"indices:data/write/update", "indices:data/write/bulk[s]", "indices:data/write/delete", "indices:data/write/bulk[s]")
			.on(WRITE_SONG_INDEX_NAME),
			new Role("transcription-role")
				.indexPermissions("indices:data/write/index", "indices:admin/create", "indices:data/write/bulk[s]", "indices:admin/mapping/put")
				.on(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ),
			new Role("limited-write-index-restore-role")
				.indexPermissions("indices:data/write/index", "indices:admin/create", "indices:data/read/search")
				.on(RESTORED_SONG_INDEX_NAME));


	/**
	* User who is allowed read both index {@link #SONG_INDEX_NAME} and {@link #PROHIBITED_SONG_INDEX_NAME}
	*/
	static final User DOUBLE_READER_USER = new User("double_read_user")
		.roles(new Role("full-song-reader").indexPermissions("indices:data/read/search")
			.on(SONG_INDEX_NAME, PROHIBITED_SONG_INDEX_NAME));

	static final User REINDEXING_USER = new User("reindexing_user")
		.roles(new Role("song-reindexing-target-write")
				.clusterPermissions("indices:data/write/reindex", "indices:data/write/bulk")
				.indexPermissions("indices:admin/create", "indices:data/write/index", "indices:data/write/bulk[s]", "indices:admin/mapping/put")
				.on(WRITE_SONG_INDEX_NAME),
			new Role("song-reindexing-source-read")
				.clusterPermissions("indices:data/read/scroll")
				.indexPermissions("indices:data/read/search")
				.on(SONG_INDEX_NAME));

	private Client internalClient;

	@ClassRule
	public static final LocalCluster cluster = new LocalCluster.Builder()
		.clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS).anonymousAuth(false)
		.authc(AUTHC_HTTPBASIC_INTERNAL).users(ADMIN_USER, LIMITED_READ_USER, LIMITED_WRITE_USER, DOUBLE_READER_USER, REINDEXING_USER)
		.build();

	@BeforeClass
	public static void createTestData() {
		try(Client client = cluster.getInternalNodeClient()){
			client.prepareIndex(SONG_INDEX_NAME).setId(ID_S1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0]).get();
			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new AliasActions(ADD).indices(SONG_INDEX_NAME).alias(SONG_LYRICS_ALIAS))).actionGet();
			client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(SONG_INDEX_NAME).id(ID_S2).source(SONGS[1])).actionGet();
			client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(SONG_INDEX_NAME).id(ID_S3).source(SONGS[2])).actionGet();

			client.prepareIndex(PROHIBITED_SONG_INDEX_NAME).setId(ID_P4).setSource(SONGS[3]).setRefreshPolicy(IMMEDIATE).get();
			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new AliasActions(ADD).indices(PROHIBITED_SONG_INDEX_NAME).alias(PROHIBITED_SONG_ALIAS))).actionGet();

			client.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(new AliasActions(ADD).indices(SONG_INDEX_NAME, PROHIBITED_SONG_INDEX_NAME).alias(COLLECTIVE_INDEX_ALIAS))).actionGet();
			var createTemplateRequest = new org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest(UNDELETABLE_TEMPLATE_NAME);
			createTemplateRequest.patterns(List.of("pattern-does-not-match-to-any-index"));
			createTemplateRequest.alias(new Alias(ALIAS_FROM_UNDELETABLE_TEMPLATE));
			client.admin().indices().putTemplate(createTemplateRequest).actionGet();

			client.admin().cluster().putRepository(new PutRepositoryRequest(UNUSED_SNAPSHOT_REPOSITORY_NAME).type("fs").settings(Map.of("location", cluster.getSnapshotDirPath()))).actionGet();
		}
	}

	@Before
	public void retrieveClusterClient() {
		this.internalClient = cluster.getInternalNodeClient();
	}

	@After
	public void cleanData() throws ExecutionException, InterruptedException {
		Stopwatch stopwatch = Stopwatch.createStarted();
		IndicesAdminClient indices = internalClient.admin().indices();
		for(String indexToBeDeleted : List.of(WRITE_SONG_INDEX_NAME, INDEX_NAME_SONG_TRANSCRIPTION_JAZZ, RESTORED_SONG_INDEX_NAME)) {
			IndicesExistsRequest indicesExistsRequest = new IndicesExistsRequest(indexToBeDeleted);
			var indicesExistsResponse = indices.exists(indicesExistsRequest).get();
			if (indicesExistsResponse.isExists()) {
				DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(indexToBeDeleted);
				indices.delete(deleteIndexRequest).actionGet();
				Awaitility.await().until(() -> indices.exists(indicesExistsRequest).get().isExists() == false);
			}
		}

		for(String aliasToBeDeleted : List.of(TEMPORARY_ALIAS_NAME, ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002)) {
			if(indices.exists(new IndicesExistsRequest(aliasToBeDeleted)).get().isExists()) {
				AliasActions aliasAction = new AliasActions(AliasActions.Type.REMOVE).indices(SONG_INDEX_NAME).alias(aliasToBeDeleted);
				internalClient.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(aliasAction)).get();
			}
		}

		GetIndexTemplatesResponse response = indices.getTemplates(new GetIndexTemplatesRequest(MUSICAL_INDEX_TEMPLATE)).get();
		for(IndexTemplateMetadata metadata : response.getIndexTemplates()) {
			indices.deleteTemplate(new DeleteIndexTemplateRequest(metadata.getName())).get();
		}

		ClusterAdminClient clusterClient = internalClient.admin().cluster();
		try {
			clusterClient.deleteRepository(new DeleteRepositoryRequest(TEST_SNAPSHOT_REPOSITORY_NAME)).actionGet();
		} catch (RepositoryMissingException e) {
			log.debug("Repository '{}' does not exist. This is expected in most of test cases", TEST_SNAPSHOT_REPOSITORY_NAME, e);
		}
		internalClient.close();
		log.debug("Cleaning data after test took {}", stopwatch.stop());
	}

	@Test
	public void shouldSearchForDocuments_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
		}
	}

	@Test
	public void shouldSearchForDocuments_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(PROHIBITED_SONG_INDEX_NAME, QUERY_TITLE_POISON);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldSearchForDocumentsViaAlias_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(SONG_LYRICS_ALIAS, QUERY_TITLE_MAGNUM_OPUS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
		}
	}

	@Test
	public void shouldSearchForDocumentsViaAlias_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(PROHIBITED_SONG_ALIAS, QUERY_TITLE_POISON);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldBeAbleToSearchSongViaMultiIndexAlias_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(COLLECTIVE_INDEX_ALIAS, QUERY_TITLE_NEXT_SONG);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S3));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_NEXT_SONG));
		}
	}

	@Test
	public void shouldBeAbleToSearchAllIndexes_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(QUERY_TITLE_MAGNUM_OPUS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
		}
	}

	@Test
	public void shouldBeAbleToSearchSongViaMultiIndexAlias_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(COLLECTIVE_INDEX_ALIAS, QUERY_TITLE_POISON);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldBeAbleToSearchAllIndexes_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest(QUERY_TITLE_MAGNUM_OPUS);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldBeAbleToSearchSongIndexesWithAsterisk_prohibitedSongIndex_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest("*" + SONG_INDEX_NAME, QUERY_TITLE_POISON);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, PROHIBITED_SONG_INDEX_NAME, ID_P4));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_POISON));
		}
	}

	@Test
	public void shouldBeAbleToSearchSongIndexesWithAsterisk_singIndex_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest("*" + SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S3));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_NEXT_SONG));
		}
	}

	@Test
	public void shouldBeAbleToSearchSongIndexesWithAsterisk_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest("*" + SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldFindSongUsingDslQuery_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = new SearchRequest(SONG_INDEX_NAME);
			SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
			BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery();
			boolQueryBuilder.filter(QueryBuilders.regexpQuery(FIELD_ARTIST, "f.+"));
			boolQueryBuilder.filter(new MatchQueryBuilder(FIELD_TITLE, TITLE_MAGNUM_OPUS));
			searchSourceBuilder.query(boolQueryBuilder);
			searchRequest.source(searchSourceBuilder);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
		}
	}

	@Test
	public void shouldFindSongUsingDslQuery_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = new SearchRequest(PROHIBITED_SONG_INDEX_NAME);
			SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
			BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery();
			boolQueryBuilder.filter(QueryBuilders.regexpQuery(FIELD_ARTIST, "n.+"));
			boolQueryBuilder.filter(new MatchQueryBuilder(FIELD_TITLE, TITLE_POISON));
			searchSourceBuilder.query(boolQueryBuilder);
			searchRequest.source(searchSourceBuilder);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldPerformSearchWithAllIndexAlias_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
			assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
			assertThat(searchResponse, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
		}
	}

	@Test
	public void shouldPerformSearchWithAllIndexAlias_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldScrollOverSearchResults_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = searchRequestWithScroll(SONG_INDEX_NAME, 2);
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
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
			SearchRequest searchRequest = searchRequestWithScroll(SONG_INDEX_NAME, 2);
			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);
			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containNotEmptyScrollingId());

			SearchScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

			assertThatThrownBy(() -> restHighLevelClient.scroll(scrollRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldGetDocument_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			GetResponse response = restHighLevelClient.get(new GetRequest(SONG_INDEX_NAME, ID_S1), DEFAULT);

			assertThat(response, containDocument(SONG_INDEX_NAME, ID_S1));
			assertThat(response, documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS));
		}
	}

	@Test
	public void shouldGetDocument_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			GetRequest getRequest = new GetRequest(PROHIBITED_SONG_INDEX_NAME, ID_P4);
			assertThatThrownBy(() -> restHighLevelClient.get(getRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldPerformMultiGetDocuments_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			MultiGetRequest request = new MultiGetRequest();
			request.add(new Item(SONG_INDEX_NAME, ID_S1));
			request.add(new Item(SONG_INDEX_NAME, ID_S2));

			MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

			assertThat(response, is(notNullValue()));
			MultiGetItemResponse[] responses = response.getResponses();
			assertThat(responses, arrayWithSize(2));
			Matcher<MultiGetItemResponse> withNullFailureProperty = hasProperty("failure", nullValue());
			assertThat(responses, arrayContaining(withNullFailureProperty, withNullFailureProperty));

			assertThat(responses[0].getResponse(), allOf(
				containDocument(SONG_INDEX_NAME, ID_S1),
				documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS))
			);
			assertThat(responses[1].getResponse(),  allOf(
				containDocument(SONG_INDEX_NAME, ID_S2),
				documentContainField(FIELD_TITLE, TITLE_SONG_1_PLUS_1))
			);
		}
	}

	@Test
	public void shouldPerformMultiGetDocuments_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
			MultiGetRequest request = new MultiGetRequest();
			request.add(new Item(SONG_INDEX_NAME, ID_S1));

			assertThatThrownBy(() -> restHighLevelClient.mget(request, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldPerformMultiGetDocuments_partiallyPositive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			MultiGetRequest request = new MultiGetRequest();
			request.add(new Item(SONG_INDEX_NAME, ID_S1));
			request.add(new Item(PROHIBITED_SONG_INDEX_NAME, ID_P4));

			MultiGetResponse response =  restHighLevelClient.mget(request, DEFAULT);

			assertThat(request, notNullValue());
			MultiGetItemResponse[] responses = response.getResponses();
			assertThat(responses, arrayWithSize(2));
			assertThat(responses, arrayContaining(
				hasProperty("failure", nullValue()),
				hasProperty("failure", notNullValue())
			));
			assertThat(responses[1].getFailure().getFailure(), statusException(INTERNAL_SERVER_ERROR));
			assertThat(responses[1].getFailure().getFailure(), errorMessageContain("security_exception"));
		}
	}

	@Test
	public void shouldBeAllowedToPerformMulitSearch_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			MultiSearchRequest request = new MultiSearchRequest();
			request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
			request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

			MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

			assertThat(response, notNullValue());
			MultiSearchResponse.Item[] responses = response.getResponses();
			assertThat(responses, Matchers.arrayWithSize(2));
			assertThat(responses, arrayContaining(
				notNullValue(),
				notNullValue()
			));
			assertThat(responses[0].getFailure(), nullValue());
			assertThat(responses[1].getFailure(), nullValue());

			assertThat(responses[0].getResponse(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
			assertThat(responses[0].getResponse(), searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
			assertThat(responses[1].getResponse(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_NEXT_SONG));
			assertThat(responses[1].getResponse(), searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S3));
		}
	}

	@Test
	public void shouldBeAllowedToPerformMulitSearch_partiallyPositive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			MultiSearchRequest request = new MultiSearchRequest();
			request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
			request.add(queryStringQueryRequest(PROHIBITED_SONG_INDEX_NAME, QUERY_TITLE_POISON));

			MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

			assertThat(response, notNullValue());
			MultiSearchResponse.Item[] responses = response.getResponses();
			assertThat(responses, Matchers.arrayWithSize(2));
			assertThat(responses, arrayContaining(notNullValue(), notNullValue()));
			assertThat(responses[0].getFailure(), nullValue());
			assertThat(responses[1].getFailure(), statusException(INTERNAL_SERVER_ERROR));
			assertThat(responses[1].getFailure(), errorMessageContain("security_exception"));
			assertThat(responses[1].getResponse(), nullValue());
		}
	}

	@Test
	public void shouldBeAllowedToPerformMulitSearch_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
			MultiSearchRequest request = new MultiSearchRequest();
			request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
			request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

			assertThatThrownBy(() -> restHighLevelClient.msearch(request, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldAggregateDataAndComputeAverage_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			final String aggregationName = "averageStars";
			SearchRequest searchRequest = averageAggregationRequest(SONG_INDEX_NAME, aggregationName, FIELD_STARS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
		}
	}

	@Test
	public void shouldAggregateDataAndComputeAverage_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = averageAggregationRequest(PROHIBITED_SONG_INDEX_NAME, "averageStars", FIELD_STARS);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldPerformStatAggregation_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			final String aggregationName = "statsStars";
			SearchRequest searchRequest = statsAggregationRequest(SONG_INDEX_NAME, aggregationName, FIELD_STARS);

			SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);

			assertThat(searchResponse, isSuccessfulSearchResponse());
			assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "stats"));
		}
	}

	@Test
	public void shouldPerformStatAggregation_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SearchRequest searchRequest = statsAggregationRequest(PROHIBITED_SONG_INDEX_NAME, "statsStars", FIELD_STARS);

			assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldIndexDocumentInBulkRequest_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			BulkRequest bulkRequest = new BulkRequest();
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1]));
			bulkRequest.setRefreshPolicy(IMMEDIATE);

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, successBulkResponse());
			assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, "one"));
			assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, "two"));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, TITLE_MAGNUM_OPUS));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1));
		}
	}

	@Test
	public void shouldIndexDocumentInBulkRequest_partiallyPositive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			BulkRequest bulkRequest = new BulkRequest();
			bulkRequest.add(new IndexRequest(SONG_INDEX_NAME).id("one").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1]));
			bulkRequest.setRefreshPolicy(IMMEDIATE);

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, bulkResponseContainExceptions(0, allOf(
				statusException(INTERNAL_SERVER_ERROR),
				errorMessageContain("security_exception")
			)));
			assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, "two"));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1));
		}
	}

	@Test
	public void shouldIndexDocumentInBulkRequest_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			BulkRequest bulkRequest = new BulkRequest();
			bulkRequest.add(new IndexRequest(SONG_INDEX_NAME).id("one").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(SONG_INDEX_NAME).id("two").source(SONGS[1]));
			bulkRequest.setRefreshPolicy(IMMEDIATE);

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, allOf(
				failureBulkResponse(),
				bulkResponseContainExceptions(statusException(INTERNAL_SERVER_ERROR)),
				bulkResponseContainExceptions(errorMessageContain("security_exception"))
			));
			assertThat(internalClient, not(clusterContainsDocument(SONG_INDEX_NAME, "one")));
			assertThat(internalClient, not(clusterContainsDocument(SONG_INDEX_NAME, "two")));
		}
	}

	@Test
	public void shouldUpdateDocumentsInBulk_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			final String titleOne = "shape of my mind";
			final String titleTwo = "forgiven";
			BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1]));
			restHighLevelClient.bulk(bulkRequest, DEFAULT);
			bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new UpdateRequest(WRITE_SONG_INDEX_NAME, "one").doc(Map.of(FIELD_TITLE, titleOne)));
			bulkRequest.add(new UpdateRequest(WRITE_SONG_INDEX_NAME, "two").doc(Map.of(FIELD_TITLE, titleTwo)));

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, successBulkResponse());
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, titleOne));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, titleTwo));
		}
	}

	@Test
	public void shouldUpdateDocumentsInBulk_partiallyPositive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			final String titleOne = "shape of my mind";
			BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0]));
			restHighLevelClient.bulk(bulkRequest, DEFAULT);
			bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new UpdateRequest(WRITE_SONG_INDEX_NAME, "one").doc(Map.of(FIELD_TITLE, titleOne)));
			bulkRequest.add(new UpdateRequest(SONG_INDEX_NAME, ID_S2).doc(Map.of(FIELD_TITLE, "forgiven")));

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, bulkResponseContainExceptions(1, allOf(
				statusException(INTERNAL_SERVER_ERROR),
				errorMessageContain("security_exception")
			)));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, titleOne));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S2, FIELD_TITLE, TITLE_SONG_1_PLUS_1));
		}
	}

	@Test
	public void shouldUpdateDocumentsInBulk_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new UpdateRequest(SONG_INDEX_NAME, ID_S1).doc(Map.of(FIELD_TITLE, "shape of my mind")));
			bulkRequest.add(new UpdateRequest(SONG_INDEX_NAME, ID_S2).doc(Map.of(FIELD_TITLE, "forgiven")));

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, allOf(
				failureBulkResponse(),
				bulkResponseContainExceptions(statusException(INTERNAL_SERVER_ERROR)),
				bulkResponseContainExceptions(errorMessageContain("security_exception"))
			));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S1, FIELD_TITLE, TITLE_MAGNUM_OPUS));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S2, FIELD_TITLE, TITLE_SONG_1_PLUS_1));
		}
	}

	@Test
	public void shouldDeleteDocumentInBulk_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("three").source(SONGS[2]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("four").source(SONGS[3]));
			assertThat(restHighLevelClient.bulk(bulkRequest, DEFAULT), successBulkResponse());
			bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "one"));
			bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "three"));

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, successBulkResponse());
			assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, "one")));
			assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, "three")));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "four", FIELD_TITLE, TITLE_POISON));
		}
	}

	@Test
	public void shouldDeleteDocumentInBulk_partiallyPositive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1]));
			assertThat(restHighLevelClient.bulk(bulkRequest, DEFAULT), successBulkResponse());
			bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "one"));
			bulkRequest.add(new DeleteRequest(SONG_INDEX_NAME, ID_S3));

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);
			assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, "one")));

			assertThat(response, bulkResponseContainExceptions(1, allOf(
				statusException(INTERNAL_SERVER_ERROR),
				errorMessageContain("security_exception")
			)));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S3, FIELD_TITLE, TITLE_NEXT_SONG));
		}
	}

	@Test
	public void shouldDeleteDocumentInBulk_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
			bulkRequest.add(new DeleteRequest(SONG_INDEX_NAME, ID_S1));
			bulkRequest.add(new DeleteRequest(SONG_INDEX_NAME, ID_S3));

			BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

			assertThat(response, allOf(
				failureBulkResponse(),
				bulkResponseContainExceptions(statusException(INTERNAL_SERVER_ERROR)),
				bulkResponseContainExceptions(errorMessageContain("security_exception"))
			));
			assertThat(internalClient, clusterContainsDocument(SONG_INDEX_NAME, ID_S1));
			assertThat(internalClient, clusterContainsDocument(SONG_INDEX_NAME, ID_S3));
		}
	}

	@Test
	public void shouldReindexDocuments_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(REINDEXING_USER)) {
			ReindexRequest reindexRequest = new ReindexRequest().setSourceIndices(SONG_INDEX_NAME).setDestIndex(WRITE_SONG_INDEX_NAME);

			BulkByScrollResponse response = restHighLevelClient.reindex(reindexRequest, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.getBulkFailures(), empty());
			assertThat(response.getSearchFailures(), empty());
			assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_S1));
			assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_S2));
			assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_S3));
		}
	}

	@Test
	public void shouldReindexDocuments_negativeSource() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(REINDEXING_USER)) {
			ReindexRequest reindexRequest = new ReindexRequest().setSourceIndices(PROHIBITED_SONG_INDEX_NAME).setDestIndex(WRITE_SONG_INDEX_NAME);

			assertThatThrownBy(() -> restHighLevelClient.reindex(reindexRequest, DEFAULT), statusException(FORBIDDEN));
			assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_P4)));
		}
	}

	@Test
	public void shouldReindexDocuments_negativeDestination() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(REINDEXING_USER)) {
			ReindexRequest reindexRequest = new ReindexRequest().setSourceIndices(SONG_INDEX_NAME).setDestIndex(PROHIBITED_SONG_INDEX_NAME);

			assertThatThrownBy(() -> restHighLevelClient.reindex(reindexRequest, DEFAULT), statusException(FORBIDDEN));
			assertThat(internalClient, not(clusterContainsDocument(PROHIBITED_SONG_INDEX_NAME, ID_S1)));
			assertThat(internalClient, not(clusterContainsDocument(PROHIBITED_SONG_INDEX_NAME, ID_S2)));
			assertThat(internalClient, not(clusterContainsDocument(PROHIBITED_SONG_INDEX_NAME, ID_S3)));
		}
	}

	@Test
	public void shouldReindexDocuments_negativeSourceAndDestination() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(REINDEXING_USER)) {
			ReindexRequest reindexRequest = new ReindexRequest().setSourceIndices(PROHIBITED_SONG_INDEX_NAME).setDestIndex(SONG_INDEX_NAME);

			assertThatThrownBy(() -> restHighLevelClient.reindex(reindexRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldCreateAlias_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			AliasActions aliasAction = new AliasActions(ADD).indices(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
			IndicesAliasesRequest indicesAliasesRequest =  new IndicesAliasesRequest().addAliasAction(aliasAction);

			var response = restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.isAcknowledged(), equalTo(true));
			assertThat(internalClient, clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_S1));
		}
	}

	@Test
	public void shouldCreateAlias_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			AliasActions aliasAction = new AliasActions(ADD).indices(PROHIBITED_SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
			IndicesAliasesRequest indicesAliasesRequest =  new IndicesAliasesRequest().addAliasAction(aliasAction);

			assertThatThrownBy(() -> restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT), statusException(FORBIDDEN));

			assertThat(internalClient, not(clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_P4)));
		}
	}

	@Test
	public void shouldDeleteAlias_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			AliasActions aliasAction = new AliasActions(ADD).indices(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
			IndicesAliasesRequest indicesAliasesRequest =  new IndicesAliasesRequest().addAliasAction(aliasAction);
			restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT);
			aliasAction = new AliasActions(REMOVE).indices(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
			indicesAliasesRequest =  new IndicesAliasesRequest().addAliasAction(aliasAction);

			var response = restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.isAcknowledged(), equalTo(true));
			assertThat(internalClient, not(clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_S1)));
		}
	}

	@Test
	public void shouldDeleteAlias_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			AliasActions aliasAction = new AliasActions(REMOVE).indices(PROHIBITED_SONG_INDEX_NAME).alias(PROHIBITED_SONG_ALIAS);
			IndicesAliasesRequest indicesAliasesRequest =  new IndicesAliasesRequest().addAliasAction(aliasAction);

			assertThatThrownBy(() -> restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT), statusException(FORBIDDEN));

			assertThat(internalClient, clusterContainsDocument(PROHIBITED_SONG_INDEX_NAME, ID_P4));
		}
	}

	@Test
	public void shouldCreateIndexTemplate_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE)
				.patterns(List.of(TEMPLATE_INDEX_PREFIX))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002));

			var response = restHighLevelClient.indices().putTemplate(request, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.isAcknowledged(), equalTo(true));
			assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE ));
			String documentId = "0001";
			IndexRequest indexRequest = new IndexRequest(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ).id(documentId).source(SONGS[0])
				.setRefreshPolicy(IMMEDIATE);
			restHighLevelClient.index(indexRequest, DEFAULT);
			assertThat(internalClient, clusterContainsDocument(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ, documentId));
			assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, documentId));
			assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, documentId));
		}
	}

	@Test
	public void shouldCreateIndexTemplate_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE)
				.patterns(List.of(TEMPLATE_INDEX_PREFIX))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002));

			assertThatThrownBy(() -> restHighLevelClient.indices().putTemplate(request, DEFAULT), statusException(FORBIDDEN));
			assertThat(internalClient, not(clusterContainTemplate(MUSICAL_INDEX_TEMPLATE )));
		}
	}

	@Test
	public void shouldDeleteTemplate_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE)
				.patterns(List.of(TEMPLATE_INDEX_PREFIX));
			restHighLevelClient.indices().putTemplate(request, DEFAULT);
			assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
			DeleteIndexTemplateRequest deleteRequest = new DeleteIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE);

			var response = restHighLevelClient.indices().deleteTemplate(deleteRequest, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.isAcknowledged(), equalTo(true));
			assertThat(internalClient, not(clusterContainTemplate(MUSICAL_INDEX_TEMPLATE)));
		}
	}

	@Test
	public void shouldDeleteTemplate_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			DeleteIndexTemplateRequest deleteRequest = new DeleteIndexTemplateRequest(UNDELETABLE_TEMPLATE_NAME);

			assertThatThrownBy(() -> restHighLevelClient.indices().deleteTemplate(deleteRequest, DEFAULT), statusException(FORBIDDEN));

			assertThat(internalClient, clusterContainTemplate(UNDELETABLE_TEMPLATE_NAME));
		}
	}

	@Test
	public void shouldUpdateTemplate_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE)
				.patterns(List.of(TEMPLATE_INDEX_PREFIX))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002));
			restHighLevelClient.indices().putTemplate(request, DEFAULT);
			assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
			request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE)
				.patterns(List.of(TEMPLATE_INDEX_PREFIX))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003));

			var response = restHighLevelClient.indices().putTemplate(request, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.isAcknowledged(), equalTo(true));
			String documentId = "000one";
			IndexRequest indexRequest = new IndexRequest(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ).id(documentId).source(SONGS[0])
				.setRefreshPolicy(IMMEDIATE);
			restHighLevelClient.index(indexRequest, DEFAULT);
			assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
			assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003, documentId));
			assertThat(internalClient, not(clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, documentId)));
			assertThat(internalClient, not(clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, documentId)));
		}
	}
	@Test
	public void shouldUpdateTemplate_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			PutIndexTemplateRequest request = new PutIndexTemplateRequest(UNDELETABLE_TEMPLATE_NAME)
				.patterns(List.of(TEMPLATE_INDEX_PREFIX))
				.alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003));

			assertThatThrownBy(() -> restHighLevelClient.indices().putTemplate(request, DEFAULT), statusException(FORBIDDEN));
			assertThat(internalClient, clusterContainTemplateWithAlias(UNDELETABLE_TEMPLATE_NAME, ALIAS_FROM_UNDELETABLE_TEMPLATE));
			assertThat(internalClient, not(clusterContainTemplateWithAlias(UNDELETABLE_TEMPLATE_NAME, ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003)));
		}
	}

	@Test
	public void shouldGetFieldCapabilitiesForAllIndexes_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
			FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().fields(FIELD_TITLE);

			FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.get(), aMapWithSize(1));
			assertThat(response.getIndices(), arrayWithSize(2));
			assertThat(response.getField(FIELD_TITLE), hasKey("text"));
			assertThat(response.getIndices(), arrayContainingInAnyOrder(SONG_INDEX_NAME, PROHIBITED_SONG_INDEX_NAME));
		}
	}

	@Test
	public void shouldGetFieldCapabilitiesForAllIndexes_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().fields(FIELD_TITLE);

			assertThatThrownBy(() ->  restHighLevelClient.fieldCaps(request, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldGetFieldCapabilitiesForParticularIndex_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(SONG_INDEX_NAME).fields(FIELD_TITLE);

			FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

			assertThat(response, notNullValue());
			assertThat(response.get(), aMapWithSize(1));
			assertThat(response.getIndices(), arrayWithSize(1));
			assertThat(response.getField(FIELD_TITLE), hasKey("text"));
			assertThat(response.getIndices(), arrayContainingInAnyOrder(SONG_INDEX_NAME));
		}
	}

	@Test
	public void shouldGetFieldCapabilitiesForParticularIndex_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(PROHIBITED_SONG_INDEX_NAME).fields(FIELD_TITLE);

			assertThatThrownBy(() -> restHighLevelClient.fieldCaps(request, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldCreateSnapshotRepository_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			String snapshotDirPath = cluster.getSnapshotDirPath();

			var response = steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotDirPath, "fs");

			assertThat(response, notNullValue());
			assertThat(response.isAcknowledged(), equalTo(true));
			assertThat(internalClient, clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME));
		}
	}

	@Test
	public void shouldCreateSnapshotRepository_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			String snapshotDirPath = cluster.getSnapshotDirPath();

			assertThatThrownBy(() -> steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotDirPath, "fs"), statusException(FORBIDDEN));
			assertThat(internalClient, not(clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME)));
		}
	}

	@Test
	public void shouldDeleteSnapshotRepository_positive() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
			assertThat(internalClient, clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME));

			var response = steps.deleteSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME);

			assertThat(response, notNullValue());
			assertThat(response.isAcknowledged(), equalTo(true));
			assertThat(internalClient, not(clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME)));
		}
	}

	@Test
	public void shouldDeleteSnapshotRepository_negative() throws IOException {
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);

			assertThatThrownBy(() -> steps.deleteSnapshotRepository(UNUSED_SNAPSHOT_REPOSITORY_NAME), statusException(FORBIDDEN));
			assertThat(internalClient, clusterContainsSnapshotRepository(UNUSED_SNAPSHOT_REPOSITORY_NAME));
		}
	}

	@Test
	public void shouldCreateSnapshot_positive() throws IOException {
		final String snapshotName = "snapshot-positive-test";
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

			CreateSnapshotResponse response = steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);

			assertThat(response, notNullValue());
			assertThat(response.status(), equalTo(RestStatus.ACCEPTED));
			steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
			assertThat(internalClient, clusterContainSuccessSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName));
		}
	}

	@Test
	public void shouldCreateSnapshot_negative() throws IOException {
		final String snapshotName = "snapshot-negative-test";
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);

			assertThatThrownBy(() -> steps.createSnapshot(UNUSED_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME), statusException(FORBIDDEN));

			assertThat(internalClient, snapshotInClusterDoesNotExists(UNUSED_SNAPSHOT_REPOSITORY_NAME, snapshotName));
		}
	}

	@Test
	public void shouldDeleteSnapshot_positive() throws IOException {
		String snapshotName = "delete-snapshot-positive";
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			restHighLevelClient.snapshot();
			steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
			steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);
			steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

			var response = steps.deleteSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

			assertThat(response.isAcknowledged(), equalTo(true));
			assertThat(internalClient, snapshotInClusterDoesNotExists(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName));
		}
	}

	@Test
	public void shouldDeleteSnapshot_negative() throws IOException {
		String snapshotName = "delete-snapshot-negative";
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
			steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);
			steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
		}
		try(RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			assertThatThrownBy(() -> steps.deleteSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName), statusException(FORBIDDEN));

			assertThat(internalClient, clusterContainSuccessSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName));
		}
	}

	@Test
	public void shouldRestoreSnapshot_positive() throws IOException {
		final String snapshotName = "restore-snapshot-positive";
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			// 1. create some documents
			BulkRequest bulkRequest = new BulkRequest();
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Eins").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Zwei").source(SONGS[1]));
			bulkRequest.setRefreshPolicy(IMMEDIATE);
			restHighLevelClient.bulk(bulkRequest, DEFAULT);

			//2. create snapshot repository
			steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

			// 3. create snapshot
			steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME) ;

			// 4. wait till snapshot is ready
			steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

			// 5. introduce some changes
			bulkRequest = new BulkRequest();
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Drei").source(SONGS[2]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Vier").source(SONGS[3]));
			bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "Eins"));
			bulkRequest.setRefreshPolicy(IMMEDIATE);
			restHighLevelClient.bulk(bulkRequest, DEFAULT);

			// 6. restore the snapshot
			var response = steps.restoreSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, "(.+)", "restored_$1");

			assertThat(response, notNullValue());
			assertThat(response.status(), equalTo(ACCEPTED));

			// 7. wait until snapshot is restored
			CountRequest countRequest = new CountRequest(RESTORED_SONG_INDEX_NAME);
			Awaitility.await().until(() -> restHighLevelClient.count(countRequest, DEFAULT).getCount() == 2);

			//8. verify that document are present in restored index
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(RESTORED_SONG_INDEX_NAME, "Eins", FIELD_TITLE, TITLE_MAGNUM_OPUS));
			assertThat(internalClient, clusterContainsDocumentWithFieldValue(RESTORED_SONG_INDEX_NAME, "Zwei", FIELD_TITLE, TITLE_SONG_1_PLUS_1));
			assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Drei")));
			assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Vier")));
		}
	}

	@Test
	public void shouldRestoreSnapshot_failureForbiddenIndex() throws IOException {
		final String snapshotName = "restore-snapshot-negative-forbidden-index";
		String restoreToIndex = "forbidden_index";
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			// 1. create some documents
			BulkRequest bulkRequest = new BulkRequest();
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Eins").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Zwei").source(SONGS[1]));
			bulkRequest.setRefreshPolicy(IMMEDIATE);
			restHighLevelClient.bulk(bulkRequest, DEFAULT);

			//2. create snapshot repository
			steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

			// 3. create snapshot
			steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME);

			// 4. wait till snapshot is ready
			steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

			// 5. restore the snapshot
			assertThatThrownBy(() -> steps.restoreSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, "(.+)", restoreToIndex),
				statusException(FORBIDDEN));


			//6. verify that document are not present in restored index
			assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Eins")));
			assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Zwei")));
		}
	}

	@Test
	public void shouldRestoreSnapshot_failureOperationForbidden() throws IOException {
		String snapshotName = "restore-snapshot-negative-forbidden-operation";
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			// 1. create some documents
			BulkRequest bulkRequest = new BulkRequest();
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Eins").source(SONGS[0]));
			bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Zwei").source(SONGS[1]));
			bulkRequest.setRefreshPolicy(IMMEDIATE);
			restHighLevelClient.bulk(bulkRequest, DEFAULT);

			//2. create snapshot repository
			steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

			// 3. create snapshot
			steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME);

			// 4. wait till snapshot is ready
			steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
		}
		// 5. restore the snapshot
		try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
			SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
			assertThatThrownBy( () -> steps.restoreSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, "(.+)", "restored_$1"),
				statusException(FORBIDDEN));

			// 6. verify that documents does not exist
			assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Eins")));
			assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Zwei")));
		}
	}
}
