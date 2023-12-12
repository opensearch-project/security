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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.base.Stopwatch;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.awaitility.Awaitility;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.repositories.delete.DeleteRepositoryRequest;
import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotResponse;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.cache.clear.ClearIndicesCacheRequest;
import org.opensearch.action.admin.indices.cache.clear.ClearIndicesCacheResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.open.OpenIndexRequest;
import org.opensearch.action.admin.indices.open.OpenIndexResponse;
import org.opensearch.action.admin.indices.settings.get.GetSettingsRequest;
import org.opensearch.action.admin.indices.settings.get.GetSettingsResponse;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.admin.indices.template.delete.DeleteIndexTemplateRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
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
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.client.Client;
import org.opensearch.client.ClusterAdminClient;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.core.CountRequest;
import org.opensearch.client.indices.CloseIndexRequest;
import org.opensearch.client.indices.CloseIndexResponse;
import org.opensearch.client.indices.CreateIndexRequest;
import org.opensearch.client.indices.CreateIndexResponse;
import org.opensearch.client.indices.GetIndexRequest;
import org.opensearch.client.indices.GetIndexResponse;
import org.opensearch.client.indices.GetMappingsRequest;
import org.opensearch.client.indices.GetMappingsResponse;
import org.opensearch.client.indices.PutIndexTemplateRequest;
import org.opensearch.client.indices.PutMappingRequest;
import org.opensearch.client.indices.ResizeRequest;
import org.opensearch.client.indices.ResizeResponse;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexTemplateMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ReindexRequest;
import org.opensearch.repositories.RepositoryMissingException;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.REMOVE;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.REMOVE_INDEX;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.ACCEPTED;
import static org.opensearch.core.rest.RestStatus.BAD_REQUEST;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.core.rest.RestStatus.INTERNAL_SERVER_ERROR;
import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;
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
import static org.opensearch.security.auditlog.impl.AuditCategory.INDEX_EVENT;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.auditPredicate;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.grantedPrivilege;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.missingPrivilege;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.userAuthenticated;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.statsAggregationRequest;
import static org.opensearch.test.framework.matcher.BulkResponseMatchers.bulkResponseContainExceptions;
import static org.opensearch.test.framework.matcher.BulkResponseMatchers.failureBulkResponse;
import static org.opensearch.test.framework.matcher.BulkResponseMatchers.successBulkResponse;
import static org.opensearch.test.framework.matcher.ClusterMatchers.aliasExists;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainSuccessSnapshot;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainTemplate;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainTemplateWithAlias;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainsDocument;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainsDocumentWithFieldValue;
import static org.opensearch.test.framework.matcher.ClusterMatchers.clusterContainsSnapshotRepository;
import static org.opensearch.test.framework.matcher.ClusterMatchers.indexExists;
import static org.opensearch.test.framework.matcher.ClusterMatchers.indexMappingIsEqualTo;
import static org.opensearch.test.framework.matcher.ClusterMatchers.indexSettingsContainValues;
import static org.opensearch.test.framework.matcher.ClusterMatchers.indexStateIsEqualTo;
import static org.opensearch.test.framework.matcher.ClusterMatchers.snapshotInClusterDoesNotExists;
import static org.opensearch.test.framework.matcher.DeleteResponseMatchers.isSuccessfulDeleteResponse;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsExactlyIndices;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.containsFieldWithNameAndType;
import static org.opensearch.test.framework.matcher.FieldCapabilitiesResponseMatchers.numberOfFieldsIsEqualTo;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containDocument;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.getIndexResponseContainsIndices;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.getMappingsResponseContainsIndices;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.getSettingsResponseContainsIndices;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.isSuccessfulClearIndicesCacheResponse;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.isSuccessfulCloseIndexResponse;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.isSuccessfulCreateIndexResponse;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.isSuccessfulOpenIndexResponse;
import static org.opensearch.test.framework.matcher.IndexResponseMatchers.isSuccessfulResizeResponse;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.isSuccessfulMultiGetResponse;
import static org.opensearch.test.framework.matcher.MultiGetResponseMatchers.numberOfGetItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.isSuccessfulMultiSearchResponse;
import static org.opensearch.test.framework.matcher.MultiSearchResponseMatchers.numberOfSearchItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.errorMessageContain;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfHitsInPageIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentWithId;
import static org.opensearch.test.framework.matcher.UpdateResponseMatchers.isSuccessfulUpdateResponse;

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
    public static final String ALIAS_CREATE_INDEX_WITH_ALIAS_POSITIVE = "alias_create_index_with_alias_positive";
    public static final String ALIAS_CREATE_INDEX_WITH_ALIAS_NEGATIVE = "alias_create_index_with_alias_negative";

    public static final String UNDELETABLE_TEMPLATE_NAME = "undeletable-template-name";

    public static final String ALIAS_FROM_UNDELETABLE_TEMPLATE = "alias-from-undeletable-template";

    public static final String TEST_SNAPSHOT_REPOSITORY_NAME = "test-snapshot-repository";

    public static final String UNUSED_SNAPSHOT_REPOSITORY_NAME = "unused-snapshot-repository";

    public static final String RESTORED_SONG_INDEX_NAME = "restored_" + WRITE_SONG_INDEX_NAME;

    public static final String UPDATE_DELETE_OPERATION_INDEX_NAME = "update_delete_index";

    public static final String DOCUMENT_TO_UPDATE_ID = "doc_to_update";

    private static final String ID_P4 = "4";
    private static final String ID_S3 = "3";
    private static final String ID_S2 = "2";
    private static final String ID_S1 = "1";

    static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    /**
    * All user read permissions are related to {@link #SONG_INDEX_NAME} index
    */
    static final User LIMITED_READ_USER = new User("limited_read_user").roles(
        new Role("limited-song-reader").clusterPermissions(
            "indices:data/read/mget",
            "indices:data/read/msearch",
            "indices:data/read/scroll"
        )
            .indexPermissions(
                "indices:data/read/search",
                "indices:data/read/get",
                "indices:data/read/mget*",
                "indices:admin/aliases",
                "indices:data/read/field_caps",
                "indices:data/read/field_caps*"
            )
            .on(SONG_INDEX_NAME)
    );

    static final User LIMITED_WRITE_USER = new User("limited_write_user").roles(
        new Role("limited-write-role").clusterPermissions(
            "indices:data/write/bulk",
            "indices:admin/template/put",
            "indices:admin/template/delete",
            "cluster:admin/repository/put",
            "cluster:admin/repository/delete",
            "cluster:admin/snapshot/create",
            "cluster:admin/snapshot/status",
            "cluster:admin/snapshot/status[nodes]",
            "cluster:admin/snapshot/delete",
            "cluster:admin/snapshot/get",
            "cluster:admin/snapshot/restore"
        )
            .indexPermissions(
                "indices:data/write/index",
                "indices:data/write/bulk[s]",
                "indices:admin/create",
                "indices:admin/mapping/put",
                "indices:data/write/update",
                "indices:data/write/bulk[s]",
                "indices:data/write/delete",
                "indices:data/write/bulk[s]"
            )
            .on(WRITE_SONG_INDEX_NAME),
        new Role("transcription-role").indexPermissions(
            "indices:data/write/index",
            "indices:admin/create",
            "indices:data/write/bulk[s]",
            "indices:admin/mapping/put"
        ).on(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ),
        new Role("limited-write-index-restore-role").indexPermissions(
            "indices:data/write/index",
            "indices:admin/create",
            "indices:data/read/search"
        ).on(RESTORED_SONG_INDEX_NAME)
    );

    /**
    * User who is allowed read both index {@link #SONG_INDEX_NAME} and {@link #PROHIBITED_SONG_INDEX_NAME}
    */
    static final User DOUBLE_READER_USER = new User("double_read_user").roles(
        new Role("full-song-reader").indexPermissions("indices:data/read/search").on(SONG_INDEX_NAME, PROHIBITED_SONG_INDEX_NAME)
    );

    static final User REINDEXING_USER = new User("reindexing_user").roles(
        new Role("song-reindexing-target-write").clusterPermissions("indices:data/write/reindex", "indices:data/write/bulk")
            .indexPermissions("indices:admin/create", "indices:data/write/index", "indices:data/write/bulk[s]", "indices:admin/mapping/put")
            .on(WRITE_SONG_INDEX_NAME),
        new Role("song-reindexing-source-read").clusterPermissions("indices:data/read/scroll")
            .indexPermissions("indices:data/read/search")
            .on(SONG_INDEX_NAME)
    );

    private Client internalClient;
    /**
    * User who is allowed to update and delete documents on index {@link #UPDATE_DELETE_OPERATION_INDEX_NAME}
    */
    static final User UPDATE_DELETE_USER = new User("update_delete_user").roles(
        new Role("document-updater").clusterPermissions("indices:data/write/bulk")
            .indexPermissions(
                "indices:data/write/update",
                "indices:data/write/index",
                "indices:data/write/bulk[s]",
                "indices:admin/mapping/put"
            )
            .on(UPDATE_DELETE_OPERATION_INDEX_NAME),
        new Role("document-remover").indexPermissions("indices:data/write/delete").on(UPDATE_DELETE_OPERATION_INDEX_NAME)
    );

    static final String INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX = "index_operations_";

    /**
    * User who is allowed to perform index-related operations on
    * indices with names prefixed by the {@link #INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX}
    */
    static final User USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES = new User("index-operation-tester").roles(
        new Role("index-manager").clusterPermissions("cluster:monitor/health")
            .indexPermissions(
                "indices:admin/create",
                "indices:admin/get",
                "indices:admin/delete",
                "indices:admin/close",
                "indices:admin/close*",
                "indices:admin/open",
                "indices:admin/resize",
                "indices:monitor/stats",
                "indices:monitor/settings/get",
                "indices:admin/settings/update",
                "indices:admin/mapping/put",
                "indices:admin/mappings/get",
                "indices:admin/cache/clear",
                "indices:admin/aliases"
            )
            .on(INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("*"))
    );

    private static final User USER_ALLOWED_TO_CREATE_INDEX = new User("user-allowed-to-create-index").roles(
        new Role("create-index-role").indexPermissions("indices:admin/create").on("*")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(
            ADMIN_USER,
            LIMITED_READ_USER,
            LIMITED_WRITE_USER,
            DOUBLE_READER_USER,
            REINDEXING_USER,
            UPDATE_DELETE_USER,
            USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES,
            USER_ALLOWED_TO_CREATE_INDEX
        )
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(SONG_INDEX_NAME).setId(ID_S1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
            client.prepareIndex(UPDATE_DELETE_OPERATION_INDEX_NAME)
                .setId(DOCUMENT_TO_UPDATE_ID)
                .setRefreshPolicy(IMMEDIATE)
                .setSource("field", "value")
                .get();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(new AliasActions(ADD).indices(SONG_INDEX_NAME).alias(SONG_LYRICS_ALIAS))
                )
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(SONG_INDEX_NAME).id(ID_S2).source(SONGS[1].asMap()))
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(SONG_INDEX_NAME).id(ID_S3).source(SONGS[2].asMap()))
                .actionGet();

            client.prepareIndex(PROHIBITED_SONG_INDEX_NAME).setId(ID_P4).setSource(SONGS[3].asMap()).setRefreshPolicy(IMMEDIATE).get();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new AliasActions(ADD).indices(PROHIBITED_SONG_INDEX_NAME).alias(PROHIBITED_SONG_ALIAS)
                    )
                )
                .actionGet();

            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new AliasActions(ADD).indices(SONG_INDEX_NAME, PROHIBITED_SONG_INDEX_NAME).alias(COLLECTIVE_INDEX_ALIAS)
                    )
                )
                .actionGet();
            var createTemplateRequest = new org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest(
                UNDELETABLE_TEMPLATE_NAME
            );
            createTemplateRequest.patterns(List.of("pattern-does-not-match-to-any-index"));
            createTemplateRequest.alias(new Alias(ALIAS_FROM_UNDELETABLE_TEMPLATE));
            client.admin().indices().putTemplate(createTemplateRequest).actionGet();

            client.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest(UNUSED_SNAPSHOT_REPOSITORY_NAME).type("fs")
                        .settings(Map.of("location", cluster.getSnapshotDirPath()))
                )
                .actionGet();
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
        List<String> indicesToBeDeleted = List.of(
            WRITE_SONG_INDEX_NAME,
            INDEX_NAME_SONG_TRANSCRIPTION_JAZZ,
            RESTORED_SONG_INDEX_NAME,
            INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("*")
        );
        for (String indexToBeDeleted : indicesToBeDeleted) {
            IndicesExistsRequest indicesExistsRequest = new IndicesExistsRequest(indexToBeDeleted);
            var indicesExistsResponse = indices.exists(indicesExistsRequest).get();
            if (indicesExistsResponse.isExists()) {
                DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(indexToBeDeleted);
                indices.delete(deleteIndexRequest).actionGet();
                Awaitility.await().ignoreExceptions().until(() -> !indices.exists(indicesExistsRequest).get().isExists());
            }
        }

        List<String> aliasesToBeDeleted = List.of(
            TEMPORARY_ALIAS_NAME,
            ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001,
            ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002,
            ALIAS_CREATE_INDEX_WITH_ALIAS_POSITIVE,
            ALIAS_CREATE_INDEX_WITH_ALIAS_NEGATIVE
        );
        for (String aliasToBeDeleted : aliasesToBeDeleted) {
            if (indices.exists(new IndicesExistsRequest(aliasToBeDeleted)).get().isExists()) {
                AliasActions aliasAction = new AliasActions(AliasActions.Type.REMOVE).indices(SONG_INDEX_NAME).alias(aliasToBeDeleted);
                internalClient.admin().indices().aliases(new IndicesAliasesRequest().addAliasAction(aliasAction)).get();
            }
        }

        GetIndexTemplatesResponse response = indices.getTemplates(new GetIndexTemplatesRequest(MUSICAL_INDEX_TEMPLATE)).get();
        for (IndexTemplateMetadata metadata : response.getIndexTemplates()) {
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldSearchForDocuments_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(PROHIBITED_SONG_INDEX_NAME, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics_index_alias/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldSearchForDocumentsViaAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(PROHIBITED_SONG_ALIAS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics_index_alias/_search")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/collective-index-alias/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(DOUBLE_READER_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAbleToSearchSongViaMultiIndexAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(COLLECTIVE_INDEX_ALIAS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/collective-index-alias/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(ADMIN_USER).withRestRequest(POST, "/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(ADMIN_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAbleToSearchAllIndexes_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(QUERY_TITLE_MAGNUM_OPUS);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/*song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(DOUBLE_READER_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/*song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(DOUBLE_READER_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAbleToSearchSongIndexesWithAsterisk_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("*" + SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/*song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(ADMIN_USER).withRestRequest(POST, "/_all/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(ADMIN_USER, "SearchRequest"));
    }

    @Test
    public void shouldPerformSearchWithAllIndexAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_all/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_search/scroll"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchScrollRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(DOUBLE_READER_USER, "SearchRequest"));
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/_search/scroll"));
        auditLogsRule.assertExactlyOne(missingPrivilege(DOUBLE_READER_USER, "SearchScrollRequest"));
    }

    @Test
    public void shouldGetDocument_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(SONG_INDEX_NAME, ID_S1), DEFAULT);

            assertThat(response, containDocument(SONG_INDEX_NAME, ID_S1));
            assertThat(response, documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/song_lyrics/_doc/1"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "GetRequest"));
    }

    @Test
    public void shouldGetDocument_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            GetRequest getRequest = new GetRequest(PROHIBITED_SONG_INDEX_NAME, ID_P4);
            assertThatThrownBy(() -> restHighLevelClient.get(getRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/prohibited_song_lyrics/_doc/4"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "GetRequest"));
    }

    @Test
    public void shouldPerformMultiGetDocuments_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            MultiGetRequest request = new MultiGetRequest();
            request.add(new Item(SONG_INDEX_NAME, ID_S1));
            request.add(new Item(SONG_INDEX_NAME, ID_S2));

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(response, is(notNullValue()));
            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(
                responses[0].getResponse(),
                allOf(containDocument(SONG_INDEX_NAME, ID_S1), documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS))
            );
            assertThat(
                responses[1].getResponse(),
                allOf(containDocument(SONG_INDEX_NAME, ID_S2), documentContainField(FIELD_TITLE, TITLE_SONG_1_PLUS_1))
            );
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_mget"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetShardRequest"));
    }

    @Test
    public void shouldPerformMultiGetDocuments_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
            MultiGetRequest request = new MultiGetRequest();
            request.add(new Item(SONG_INDEX_NAME, ID_S1));

            assertThatThrownBy(() -> restHighLevelClient.mget(request, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/_mget"));
        auditLogsRule.assertExactlyOne(missingPrivilege(DOUBLE_READER_USER, "MultiGetRequest"));
    }

    @Test
    public void shouldPerformMultiGetDocuments_partiallyPositive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            MultiGetRequest request = new MultiGetRequest();
            request.add(new Item(SONG_INDEX_NAME, ID_S1));
            request.add(new Item(PROHIBITED_SONG_INDEX_NAME, ID_P4));

            MultiGetResponse response = restHighLevelClient.mget(request, DEFAULT);

            assertThat(request, notNullValue());
            assertThat(response, not(isSuccessfulMultiGetResponse()));
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            MultiGetItemResponse[] responses = response.getResponses();
            assertThat(responses, arrayContaining(hasProperty("failure", nullValue()), hasProperty("failure", notNullValue())));
            assertThat(responses[1].getFailure().getFailure(), statusException(INTERNAL_SERVER_ERROR));
            assertThat(responses[1].getFailure().getFailure(), errorMessageContain("security_exception"));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_mget"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetShardRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "MultiGetShardRequest").withIndex(PROHIBITED_SONG_INDEX_NAME));
    }

    @Test
    public void shouldBeAllowedToPerformMulitSearch_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();

            assertThat(responses[0].getResponse(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(responses[0].getResponse(), searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
            assertThat(responses[1].getResponse(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_NEXT_SONG));
            assertThat(responses[1].getResponse(), searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S3));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_msearch"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiSearchRequest"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAllowedToPerformMulitSearch_partiallyPositive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(PROHIBITED_SONG_INDEX_NAME, QUERY_TITLE_POISON));

            MultiSearchResponse response = restHighLevelClient.msearch(request, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response, not(isSuccessfulMultiSearchResponse()));
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            MultiSearchResponse.Item[] responses = response.getResponses();
            assertThat(responses[0].getFailure(), nullValue());
            assertThat(responses[1].getFailure(), statusException(INTERNAL_SERVER_ERROR));
            assertThat(responses[1].getFailure(), errorMessageContain("security_exception"));
            assertThat(responses[1].getResponse(), nullValue());
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_msearch"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiSearchRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(PROHIBITED_SONG_INDEX_NAME));
    }

    @Test
    public void shouldBeAllowedToPerformMulitSearch_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DOUBLE_READER_USER)) {
            MultiSearchRequest request = new MultiSearchRequest();
            request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS));
            request.add(queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG));

            assertThatThrownBy(() -> restHighLevelClient.msearch(request, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/_msearch"));
        auditLogsRule.assertExactlyOne(missingPrivilege(DOUBLE_READER_USER, "MultiSearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(SONG_INDEX_NAME));
    }

    @Test
    public void shouldAggregateDataAndComputeAverage_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = averageAggregationRequest(PROHIBITED_SONG_INDEX_NAME, "averageStars", FIELD_STARS);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(PROHIBITED_SONG_INDEX_NAME));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldPerformStatAggregation_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = statsAggregationRequest(PROHIBITED_SONG_INDEX_NAME, "statsStars", FIELD_STARS);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldIndexDocumentInBulkRequest_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = new BulkRequest();
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1].asMap()));
            bulkRequest.setRefreshPolicy(IMMEDIATE);

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(response, successBulkResponse());
            assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, "one"));
            assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, "two"));
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1)
            );
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertExactlyOne(auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldIndexDocumentInBulkRequest_partiallyPositive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = new BulkRequest();
            bulkRequest.add(new IndexRequest(SONG_INDEX_NAME).id("one").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1].asMap()));
            bulkRequest.setRefreshPolicy(IMMEDIATE);

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(
                response,
                bulkResponseContainExceptions(0, allOf(statusException(INTERNAL_SERVER_ERROR), errorMessageContain("security_exception")))
            );
            assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, "two"));
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1)
            );
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertExactlyOne(auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldIndexDocumentInBulkRequest_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = new BulkRequest();
            bulkRequest.add(new IndexRequest(SONG_INDEX_NAME).id("one").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(SONG_INDEX_NAME).id("two").source(SONGS[1].asMap()));
            bulkRequest.setRefreshPolicy(IMMEDIATE);

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(
                response,
                allOf(
                    failureBulkResponse(),
                    bulkResponseContainExceptions(statusException(INTERNAL_SERVER_ERROR)),
                    bulkResponseContainExceptions(errorMessageContain("security_exception"))
                )
            );
            assertThat(internalClient, not(clusterContainsDocument(SONG_INDEX_NAME, "one")));
            assertThat(internalClient, not(clusterContainsDocument(SONG_INDEX_NAME, "two")));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest").withIndex(SONG_INDEX_NAME));
    }

    @Test
    public void shouldUpdateDocumentsInBulk_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            final String titleOne = "shape of my mind";
            final String titleTwo = "forgiven";
            BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1].asMap()));
            restHighLevelClient.bulk(bulkRequest, DEFAULT);
            bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new UpdateRequest(WRITE_SONG_INDEX_NAME, "one").doc(Map.of(FIELD_TITLE, titleOne)));
            bulkRequest.add(new UpdateRequest(WRITE_SONG_INDEX_NAME, "two").doc(Map.of(FIELD_TITLE, titleTwo)));

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(response, successBulkResponse());
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, titleOne));
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, titleTwo));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
        auditLogsRule.assertExactlyOne(auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
    }

    @Test
    public void shouldUpdateDocumentsInBulk_partiallyPositive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            final String titleOne = "shape of my mind";
            BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0].asMap()));
            restHighLevelClient.bulk(bulkRequest, DEFAULT);
            bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new UpdateRequest(WRITE_SONG_INDEX_NAME, "one").doc(Map.of(FIELD_TITLE, titleOne)));
            bulkRequest.add(new UpdateRequest(SONG_INDEX_NAME, ID_S2).doc(Map.of(FIELD_TITLE, "forgiven")));

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(
                response,
                bulkResponseContainExceptions(1, allOf(statusException(INTERNAL_SERVER_ERROR), errorMessageContain("security_exception")))
            );
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, titleOne));
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S2, FIELD_TITLE, TITLE_SONG_1_PLUS_1));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertExactlyOne(auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldUpdateDocumentsInBulk_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new UpdateRequest(SONG_INDEX_NAME, ID_S1).doc(Map.of(FIELD_TITLE, "shape of my mind")));
            bulkRequest.add(new UpdateRequest(SONG_INDEX_NAME, ID_S2).doc(Map.of(FIELD_TITLE, "forgiven")));

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(
                response,
                allOf(
                    failureBulkResponse(),
                    bulkResponseContainExceptions(statusException(INTERNAL_SERVER_ERROR)),
                    bulkResponseContainExceptions(errorMessageContain("security_exception"))
                )
            );
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S1, FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S2, FIELD_TITLE, TITLE_SONG_1_PLUS_1));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest"));
    }

    @Test
    public void shouldDeleteDocumentInBulk_positive() throws IOException {
        // create index
        Settings sourceIndexSettings = Settings.builder().put("index.number_of_replicas", 2).put("index.number_of_shards", 2).build();
        IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, sourceIndexSettings);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("three").source(SONGS[2].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("four").source(SONGS[3].asMap()));
            assertThat(restHighLevelClient.bulk(bulkRequest, DEFAULT), successBulkResponse());
            bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "one"));
            bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "three"));

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(response, successBulkResponse());
            assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, "one")));
            assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, "three")));
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1)
            );
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "four", FIELD_TITLE, TITLE_POISON));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactly(2, auditPredicate(null).withLayer(AuditLog.Origin.TRANSPORT));
        auditLogsRule.assertAtLeastTransportMessages(4, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
        auditLogsRule.assertAtLeastTransportMessages(4, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
    }

    @Test
    public void shouldDeleteDocumentInBulk_partiallyPositive() throws IOException {
        Settings indexSettings = Settings.builder().put("index.number_of_replicas", 0).put("index.number_of_shards", 1).build();
        IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("one").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("two").source(SONGS[1].asMap()));
            assertThat(restHighLevelClient.bulk(bulkRequest, DEFAULT), successBulkResponse());
            bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "one"));
            bulkRequest.add(new DeleteRequest(SONG_INDEX_NAME, ID_S3));

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);
            assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, "one")));

            assertThat(
                response,
                bulkResponseContainExceptions(1, allOf(statusException(INTERNAL_SERVER_ERROR), errorMessageContain("security_exception")))
            );
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1)
            );
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S3, FIELD_TITLE, TITLE_NEXT_SONG));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest"));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldDeleteDocumentInBulk_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(IMMEDIATE);
            bulkRequest.add(new DeleteRequest(SONG_INDEX_NAME, ID_S1));
            bulkRequest.add(new DeleteRequest(SONG_INDEX_NAME, ID_S3));

            BulkResponse response = restHighLevelClient.bulk(bulkRequest, DEFAULT);

            assertThat(
                response,
                allOf(
                    failureBulkResponse(),
                    bulkResponseContainExceptions(statusException(INTERNAL_SERVER_ERROR)),
                    bulkResponseContainExceptions(errorMessageContain("security_exception"))
                )
            );
            assertThat(internalClient, clusterContainsDocument(SONG_INDEX_NAME, ID_S1));
            assertThat(internalClient, clusterContainsDocument(SONG_INDEX_NAME, ID_S3));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest"));

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
        auditLogsRule.assertExactlyOne(userAuthenticated(REINDEXING_USER).withRestRequest(POST, "/_reindex"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "ReindexRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "SearchRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "CreateIndexRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "SearchScrollRequest"));
        auditLogsRule.assertExactlyOne(auditPredicate(INDEX_EVENT).withEffectiveUser(REINDEXING_USER));
        auditLogsRule.assertExactlyOne(missingPrivilege(REINDEXING_USER, "ClearScrollRequest"));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(REINDEXING_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldReindexDocuments_negativeSource() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(REINDEXING_USER)) {
            ReindexRequest reindexRequest = new ReindexRequest().setSourceIndices(PROHIBITED_SONG_INDEX_NAME)
                .setDestIndex(WRITE_SONG_INDEX_NAME);

            assertThatThrownBy(() -> restHighLevelClient.reindex(reindexRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_P4)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(REINDEXING_USER).withRestRequest(POST, "/_reindex"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "ReindexRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(REINDEXING_USER, "SearchRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(REINDEXING_USER).withRestRequest(POST, "/_reindex"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "ReindexRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "SearchRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(REINDEXING_USER, "BulkShardRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(REINDEXING_USER, "ClearScrollRequest"));
    }

    @Test
    public void shouldReindexDocuments_negativeSourceAndDestination() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(REINDEXING_USER)) {
            ReindexRequest reindexRequest = new ReindexRequest().setSourceIndices(PROHIBITED_SONG_INDEX_NAME).setDestIndex(SONG_INDEX_NAME);

            assertThatThrownBy(() -> restHighLevelClient.reindex(reindexRequest, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(REINDEXING_USER).withRestRequest(POST, "/_reindex"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "ReindexRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(REINDEXING_USER, "SearchRequest"));
    }

    @Test
    public void shouldUpdateDocument_positive() throws IOException {
        String newField = "newField";
        String newValue = "newValue";
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(UPDATE_DELETE_USER)) {
            UpdateRequest updateRequest = new UpdateRequest(UPDATE_DELETE_OPERATION_INDEX_NAME, DOCUMENT_TO_UPDATE_ID).doc(
                newField,
                newValue
            ).setRefreshPolicy(IMMEDIATE);

            UpdateResponse response = restHighLevelClient.update(updateRequest, DEFAULT);

            assertThat(response, isSuccessfulUpdateResponse());
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(UPDATE_DELETE_OPERATION_INDEX_NAME, DOCUMENT_TO_UPDATE_ID, newField, newValue)
            );
        }
    }

    @Test
    public void shouldUpdateDocument_negative() throws IOException {
        String newField = "newField";
        String newValue = "newValue";
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(UPDATE_DELETE_USER)) {
            UpdateRequest updateRequest = new UpdateRequest(PROHIBITED_SONG_INDEX_NAME, DOCUMENT_TO_UPDATE_ID).doc(newField, newValue)
                .setRefreshPolicy(IMMEDIATE);

            assertThatThrownBy(() -> restHighLevelClient.update(updateRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldDeleteDocument_positive() throws IOException {
        String docId = "shouldDeleteDocument_positive";
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(
                new IndexRequest(UPDATE_DELETE_OPERATION_INDEX_NAME).id(docId).source("field", "value").setRefreshPolicy(IMMEDIATE)
            ).actionGet();
            assertThat(internalClient, clusterContainsDocument(UPDATE_DELETE_OPERATION_INDEX_NAME, docId));
        }
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(UPDATE_DELETE_USER)) {
            DeleteRequest deleteRequest = new DeleteRequest(UPDATE_DELETE_OPERATION_INDEX_NAME, docId).setRefreshPolicy(IMMEDIATE);

            DeleteResponse response = restHighLevelClient.delete(deleteRequest, DEFAULT);

            assertThat(response, isSuccessfulDeleteResponse());
            assertThat(internalClient, not(clusterContainsDocument(UPDATE_DELETE_OPERATION_INDEX_NAME, docId)));
        }
    }

    @Test
    public void shouldDeleteDocument_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(UPDATE_DELETE_USER)) {
            DeleteRequest deleteRequest = new DeleteRequest(PROHIBITED_SONG_INDEX_NAME, ID_S1).setRefreshPolicy(IMMEDIATE);

            assertThatThrownBy(() -> restHighLevelClient.delete(deleteRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldCreateAlias_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            AliasActions aliasAction = new AliasActions(ADD).indices(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
            IndicesAliasesRequest indicesAliasesRequest = new IndicesAliasesRequest().addAliasAction(aliasAction);

            var response = restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response.isAcknowledged(), equalTo(true));
            assertThat(internalClient, clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_S1));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
        auditLogsRule.assertExactlyOne(auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_READ_USER));
    }

    @Test
    public void shouldCreateAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            AliasActions aliasAction = new AliasActions(ADD).indices(PROHIBITED_SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
            IndicesAliasesRequest indicesAliasesRequest = new IndicesAliasesRequest().addAliasAction(aliasAction);

            assertThatThrownBy(
                () -> restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT),
                statusException(FORBIDDEN)
            );

            assertThat(internalClient, not(clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_P4)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
    }

    @Test
    public void shouldDeleteAlias_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            AliasActions aliasAction = new AliasActions(ADD).indices(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
            IndicesAliasesRequest indicesAliasesRequest = new IndicesAliasesRequest().addAliasAction(aliasAction);
            restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT);
            aliasAction = new AliasActions(REMOVE).indices(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME);
            indicesAliasesRequest = new IndicesAliasesRequest().addAliasAction(aliasAction);

            var response = restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response.isAcknowledged(), equalTo(true));
            assertThat(internalClient, not(clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_S1)));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
        auditLogsRule.assertExactly(2, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_READ_USER));
    }

    @Test
    public void shouldDeleteAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            AliasActions aliasAction = new AliasActions(REMOVE).indices(PROHIBITED_SONG_INDEX_NAME).alias(PROHIBITED_SONG_ALIAS);
            IndicesAliasesRequest indicesAliasesRequest = new IndicesAliasesRequest().addAliasAction(aliasAction);

            assertThatThrownBy(
                () -> restHighLevelClient.indices().updateAliases(indicesAliasesRequest, DEFAULT),
                statusException(FORBIDDEN)
            );

            assertThat(internalClient, clusterContainsDocument(PROHIBITED_SONG_INDEX_NAME, ID_P4));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
    }

    @Test
    public void shouldCreateIndexTemplate_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE).patterns(List.of(TEMPLATE_INDEX_PREFIX))
                .alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001))
                .alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002));

            var response = restHighLevelClient.indices().putTemplate(request, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response.isAcknowledged(), equalTo(true));
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
            String documentId = "0001";
            IndexRequest indexRequest = new IndexRequest(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ).id(documentId)
                .source(SONGS[0].asMap())
                .setRefreshPolicy(IMMEDIATE);
            restHighLevelClient.index(indexRequest, DEFAULT);
            assertThat(internalClient, clusterContainsDocument(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ, documentId));
            assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, documentId));
            assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, documentId));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/song-transcription-jazz/_doc/0001"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutIndexTemplateRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "IndexRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertExactly(2, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldCreateIndexTemplate_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE).patterns(List.of(TEMPLATE_INDEX_PREFIX))
                .alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001))
                .alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002));

            assertThatThrownBy(() -> restHighLevelClient.indices().putTemplate(request, DEFAULT), statusException(FORBIDDEN));
            assertThat(internalClient, not(clusterContainTemplate(MUSICAL_INDEX_TEMPLATE)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "PutIndexTemplateRequest"));
    }

    @Test
    public void shouldDeleteTemplate_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE).patterns(List.of(TEMPLATE_INDEX_PREFIX));
            restHighLevelClient.indices().putTemplate(request, DEFAULT);
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
            DeleteIndexTemplateRequest deleteRequest = new DeleteIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE);

            var response = restHighLevelClient.indices().deleteTemplate(deleteRequest, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response.isAcknowledged(), equalTo(true));
            assertThat(internalClient, not(clusterContainTemplate(MUSICAL_INDEX_TEMPLATE)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(DELETE, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutIndexTemplateRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "DeleteIndexTemplateRequest"));
        auditLogsRule.assertExactly(2, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
    }

    @Test
    public void shouldDeleteTemplate_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            DeleteIndexTemplateRequest deleteRequest = new DeleteIndexTemplateRequest(UNDELETABLE_TEMPLATE_NAME);

            assertThatThrownBy(() -> restHighLevelClient.indices().deleteTemplate(deleteRequest, DEFAULT), statusException(FORBIDDEN));

            assertThat(internalClient, clusterContainTemplate(UNDELETABLE_TEMPLATE_NAME));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(DELETE, "/_template/undeletable-template-name")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "DeleteIndexTemplateRequest"));
    }

    @Test
    public void shouldUpdateTemplate_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            PutIndexTemplateRequest request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE).patterns(List.of(TEMPLATE_INDEX_PREFIX))
                .alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001))
                .alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002));
            restHighLevelClient.indices().putTemplate(request, DEFAULT);
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
            request = new PutIndexTemplateRequest(MUSICAL_INDEX_TEMPLATE).patterns(List.of(TEMPLATE_INDEX_PREFIX))
                .alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003));

            var response = restHighLevelClient.indices().putTemplate(request, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response.isAcknowledged(), equalTo(true));
            String documentId = "000one";
            IndexRequest indexRequest = new IndexRequest(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ).id(documentId)
                .source(SONGS[0].asMap())
                .setRefreshPolicy(IMMEDIATE);
            restHighLevelClient.index(indexRequest, DEFAULT);
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
            assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003, documentId));
            assertThat(internalClient, not(clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, documentId)));
            assertThat(internalClient, not(clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, documentId)));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/song-transcription-jazz/_doc/000one"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "PutIndexTemplateRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "IndexRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertExactly(3, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldUpdateTemplate_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            PutIndexTemplateRequest request = new PutIndexTemplateRequest(UNDELETABLE_TEMPLATE_NAME).patterns(
                List.of(TEMPLATE_INDEX_PREFIX)
            ).alias(new Alias(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003));

            assertThatThrownBy(() -> restHighLevelClient.indices().putTemplate(request, DEFAULT), statusException(FORBIDDEN));
            assertThat(internalClient, clusterContainTemplateWithAlias(UNDELETABLE_TEMPLATE_NAME, ALIAS_FROM_UNDELETABLE_TEMPLATE));
            assertThat(
                internalClient,
                not(clusterContainTemplateWithAlias(UNDELETABLE_TEMPLATE_NAME, ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003))
            );
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(PUT, "/_template/undeletable-template-name"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "PutIndexTemplateRequest"));
    }

    @Test
    public void shouldGetFieldCapabilitiesForAllIndexes_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().fields(FIELD_TITLE);

            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response, containsExactlyIndices(SONG_INDEX_NAME, PROHIBITED_SONG_INDEX_NAME, UPDATE_DELETE_OPERATION_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(1));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(ADMIN_USER).withRestRequest(GET, "/_field_caps"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(ADMIN_USER, "FieldCapabilitiesRequest"));
        auditLogsRule.assertExactly(3, grantedPrivilege(ADMIN_USER, "FieldCapabilitiesIndexRequest"));
    }

    @Test
    public void shouldGetFieldCapabilitiesForAllIndexes_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().fields(FIELD_TITLE);

            assertThatThrownBy(() -> restHighLevelClient.fieldCaps(request, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/_field_caps"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "FieldCapabilitiesRequest"));
    }

    @Test
    public void shouldGetFieldCapabilitiesForParticularIndex_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(SONG_INDEX_NAME).fields(FIELD_TITLE);

            FieldCapabilitiesResponse response = restHighLevelClient.fieldCaps(request, DEFAULT);

            assertThat(response, notNullValue());
            assertThat(response, containsExactlyIndices(SONG_INDEX_NAME));
            assertThat(response, numberOfFieldsIsEqualTo(1));
            assertThat(response, containsFieldWithNameAndType(FIELD_TITLE, "text"));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/song_lyrics/_field_caps"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "FieldCapabilitiesRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "FieldCapabilitiesIndexRequest"));
    }

    @Test
    public void shouldGetFieldCapabilitiesForParticularIndex_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            FieldCapabilitiesRequest request = new FieldCapabilitiesRequest().indices(PROHIBITED_SONG_INDEX_NAME).fields(FIELD_TITLE);

            assertThatThrownBy(() -> restHighLevelClient.fieldCaps(request, DEFAULT), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/prohibited_song_lyrics/_field_caps"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "FieldCapabilitiesRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
    }

    @Test
    public void shouldCreateSnapshotRepository_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            String snapshotDirPath = cluster.getSnapshotDirPath();

            assertThatThrownBy(
                () -> steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotDirPath, "fs"),
                statusException(FORBIDDEN)
            );
            assertThat(internalClient, not(clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "PutRepositoryRequest"));
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(DELETE, "/_snapshot/test-snapshot-repository")
        );
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "DeleteRepositoryRequest"));
    }

    @Test
    public void shouldDeleteSnapshotRepository_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);

            assertThatThrownBy(() -> steps.deleteSnapshotRepository(UNUSED_SNAPSHOT_REPOSITORY_NAME), statusException(FORBIDDEN));
            assertThat(internalClient, clusterContainsSnapshotRepository(UNUSED_SNAPSHOT_REPOSITORY_NAME));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(DELETE, "/_snapshot/unused-snapshot-repository")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "DeleteRepositoryRequest"));
    }

    @Test
    public void shouldCreateSnapshot_positive() throws IOException {
        final String snapshotName = "snapshot-positive-test";
        long snapshotGetCount;
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

            CreateSnapshotResponse response = steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);

            assertThat(response, notNullValue());
            assertThat(response.status(), equalTo(RestStatus.ACCEPTED));
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
            assertThat(internalClient, clusterContainSuccessSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository/snapshot-positive-test")
        );
        auditLogsRule.assertExactly(
            snapshotGetCount,
            userAuthenticated(LIMITED_WRITE_USER).withEffectiveUser(LIMITED_WRITE_USER)
                .withRestRequest(GET, "/_snapshot/test-snapshot-repository/snapshot-positive-test")
        );
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertAtLeast(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
    }

    @Test
    public void shouldCreateSnapshot_negative() throws IOException {
        final String snapshotName = "snapshot-negative-test";
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);

            assertThatThrownBy(
                () -> steps.createSnapshot(UNUSED_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME),
                statusException(FORBIDDEN)
            );

            assertThat(internalClient, snapshotInClusterDoesNotExists(UNUSED_SNAPSHOT_REPOSITORY_NAME, snapshotName));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(PUT, "/_snapshot/unused-snapshot-repository/snapshot-negative-test")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "CreateSnapshotRequest"));
    }

    @Test
    public void shouldDeleteSnapshot_positive() throws IOException {
        String snapshotName = "delete-snapshot-positive";
        long snapshotGetCount;
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            restHighLevelClient.snapshot();
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

            var response = steps.deleteSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

            assertThat(response.isAcknowledged(), equalTo(true));
            assertThat(internalClient, snapshotInClusterDoesNotExists(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository/delete-snapshot-positive")
        );
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(DELETE, "/_snapshot/test-snapshot-repository/delete-snapshot-positive")
        );
        auditLogsRule.assertExactly(
            snapshotGetCount,
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(GET, "/_snapshot/test-snapshot-repository/delete-snapshot-positive")
        );
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "DeleteSnapshotRequest"));
        auditLogsRule.assertExactly(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
    }

    @Test
    public void shouldDeleteSnapshot_negative() throws IOException {
        String snapshotName = "delete-snapshot-negative";
        long snapshotGetCount;
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
        }
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            assertThatThrownBy(() -> steps.deleteSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName), statusException(FORBIDDEN));

            assertThat(internalClient, clusterContainSuccessSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository/delete-snapshot-negative")
        );
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(DELETE, "/_snapshot/test-snapshot-repository/delete-snapshot-negative")
        );
        auditLogsRule.assertExactly(
            snapshotGetCount,
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(GET, "/_snapshot/test-snapshot-repository/delete-snapshot-negative")
        );
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "DeleteSnapshotRequest"));
        auditLogsRule.assertExactly(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
    }

    @Test
    public void shouldRestoreSnapshot_positive() throws IOException {
        final String snapshotName = "restore-snapshot-positive";
        long snapshotGetCount;
        AtomicInteger restoredCount = new AtomicInteger();
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            // 1. create some documents
            Settings indexSettings = Settings.builder().put("index.number_of_replicas", 0).put("index.number_of_shards", 1).build();
            IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);

            BulkRequest bulkRequest = new BulkRequest();
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Eins").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Zwei").source(SONGS[1].asMap()));
            bulkRequest.setRefreshPolicy(IMMEDIATE);
            restHighLevelClient.bulk(bulkRequest, DEFAULT);

            // 2. create snapshot repository
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

            // 3. create snapshot
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME);

            // 4. wait till snapshot is ready
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

            // 5. introduce some changes
            bulkRequest = new BulkRequest();
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Drei").source(SONGS[2].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Vier").source(SONGS[3].asMap()));
            bulkRequest.add(new DeleteRequest(WRITE_SONG_INDEX_NAME, "Eins"));
            bulkRequest.setRefreshPolicy(IMMEDIATE);
            restHighLevelClient.bulk(bulkRequest, DEFAULT);

            // 6. restore the snapshot
            var response = steps.restoreSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, "(.+)", "restored_$1");

            assertThat(response, notNullValue());
            assertThat(response.status(), equalTo(ACCEPTED));

            // 7. wait until snapshot is restored
            CountRequest countRequest = new CountRequest(RESTORED_SONG_INDEX_NAME);
            Awaitility.await()
                .ignoreExceptions()
                .pollInterval(100, TimeUnit.MILLISECONDS)
                .alias("Index contains proper number of documents restored from snapshot.")
                .until(() -> {
                    restoredCount.incrementAndGet();
                    return restHighLevelClient.count(countRequest, DEFAULT).getCount() == 2;
                });

            // 8. verify that document are present in restored index
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(RESTORED_SONG_INDEX_NAME, "Eins", FIELD_TITLE, TITLE_MAGNUM_OPUS)
            );
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(RESTORED_SONG_INDEX_NAME, "Zwei", FIELD_TITLE, TITLE_SONG_1_PLUS_1)
            );
            assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Drei")));
            assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Vier")));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository/restore-snapshot-positive")
        );
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(
                POST,
                "/_snapshot/test-snapshot-repository/restore-snapshot-positive/_restore"
            )
        );
        auditLogsRule.assertExactly(
            restoredCount.get(),
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/restored_write_song_index/_count")
        );
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(
            snapshotGetCount,
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(GET, "/_snapshot/test-snapshot-repository/restore-snapshot-positive")
        );
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "RestoreSnapshotRequest"));
        auditLogsRule.assertExactly(restoredCount.get(), grantedPrivilege(LIMITED_WRITE_USER, "SearchRequest"));
        auditLogsRule.assertExactly(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldRestoreSnapshot_failureForbiddenIndex() throws IOException {
        final String snapshotName = "restore-snapshot-negative-forbidden-index";
        String restoreToIndex = "forbidden_index";
        long snapshotGetCount;
        Settings indexSettings = Settings.builder().put("index.number_of_shards", 1).put("index.number_of_replicas", 0).build();
        IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {

            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            // 1. create some documents
            BulkRequest bulkRequest = new BulkRequest();
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Eins").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Zwei").source(SONGS[1].asMap()));
            bulkRequest.setRefreshPolicy(IMMEDIATE);
            restHighLevelClient.bulk(bulkRequest, DEFAULT);

            // 2. create snapshot repository
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

            // 3. create snapshot
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME);

            // 4. wait till snapshot is ready
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

            // 5. restore the snapshot
            assertThatThrownBy(
                () -> steps.restoreSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, "(.+)", restoreToIndex),
                statusException(FORBIDDEN)
            );

            // 6. verify that document are not present in restored index
            assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Eins")));
            assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Zwei")));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(
                PUT,
                "/_snapshot/test-snapshot-repository/restore-snapshot-negative-forbidden-index"
            )
        );
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(
                POST,
                "/_snapshot/test-snapshot-repository/restore-snapshot-negative-forbidden-index/_restore"
            )
        );
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(
            snapshotGetCount,
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(
                GET,
                "/_snapshot/test-snapshot-repository/restore-snapshot-negative-forbidden-index"
            )
        );
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactly(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
        auditLogsRule.assertAtLeastTransportMessages(1, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertExactlyScanAll(1, missingPrivilege(LIMITED_WRITE_USER, "RestoreSnapshotRequest"));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldRestoreSnapshot_failureOperationForbidden() throws IOException {
        String snapshotName = "restore-snapshot-negative-forbidden-operation";
        long snapshotGetCount;
        Settings indexSettings = Settings.builder().put("index.number_of_shards", 1).put("index.number_of_replicas", 0).build();
        IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            // 1. create some documents
            BulkRequest bulkRequest = new BulkRequest();
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Eins").source(SONGS[0].asMap()));
            bulkRequest.add(new IndexRequest(WRITE_SONG_INDEX_NAME).id("Zwei").source(SONGS[1].asMap()));
            bulkRequest.setRefreshPolicy(IMMEDIATE);
            restHighLevelClient.bulk(bulkRequest, DEFAULT);

            // 2. create snapshot repository
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

            // 3. create snapshot
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME);

            // 4. wait till snapshot is ready
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
        }
        // 5. restore the snapshot
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            assertThatThrownBy(
                () -> steps.restoreSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, "(.+)", "restored_$1"),
                statusException(FORBIDDEN)
            );

            // 6. verify that documents does not exist
            assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Eins")));
            assertThat(internalClient, not(clusterContainsDocument(RESTORED_SONG_INDEX_NAME, "Zwei")));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(
                PUT,
                "/_snapshot/test-snapshot-repository/restore-snapshot-negative-forbidden-operation"
            )
        );
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(
                POST,
                "/_snapshot/test-snapshot-repository/restore-snapshot-negative-forbidden-operation/_restore"
            )
        );
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(
            snapshotGetCount,
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(
                GET,
                "/_snapshot/test-snapshot-repository/restore-snapshot-negative-forbidden-operation"
            )
        );
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyScanAll(1, missingPrivilege(LIMITED_READ_USER, "RestoreSnapshotRequest"));
        auditLogsRule.assertExactly(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
        auditLogsRule.assertAtLeastTransportMessages(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    // required permissions: "indices:admin/create"
    public void createIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("create_index_positive");
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName);
            CreateIndexResponse createIndexResponse = restHighLevelClient.indices().create(createIndexRequest, DEFAULT);

            assertThat(createIndexResponse, isSuccessfulCreateIndexResponse(indexName));
            assertThat(cluster, indexExists(indexName));
        }
    }

    @Test
    public void createIndex_negative() throws IOException {
        String indexName = "create_index_negative";
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName);

            assertThatThrownBy(() -> restHighLevelClient.indices().create(createIndexRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(indexName)));
        }
    }

    @Test
    // required permissions: "indices:admin/get"
    public void checkIfIndexExists_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("index_exists_positive");
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            boolean exists = restHighLevelClient.indices().exists(new GetIndexRequest(indexName), DEFAULT);

            assertThat(exists, is(false));
        }
    }

    @Test
    public void checkIfIndexExists_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "index_exists_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            assertThatThrownBy(
                () -> restHighLevelClient.indices().exists(new GetIndexRequest(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .exists(new GetIndexRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> restHighLevelClient.indices().exists(new GetIndexRequest("*"), DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/delete"
    public void deleteIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("delete_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(indexName);
            var response = restHighLevelClient.indices().delete(deleteIndexRequest, DEFAULT);

            assertThat(response.isAcknowledged(), is(true));
            assertThat(cluster, not(indexExists(indexName)));
        }
    }

    @Test
    public void deleteIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "delete_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices().delete(new DeleteIndexRequest(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .delete(new DeleteIndexRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices().delete(new DeleteIndexRequest("*"), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: indices:admin/aliases, indices:admin/delete
    public void shouldDeleteIndexByAliasRequest_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("delete_index_by_alias_request_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            IndicesAliasesRequest request = new IndicesAliasesRequest().addAliasAction(new AliasActions(REMOVE_INDEX).indices(indexName));

            var response = restHighLevelClient.indices().updateAliases(request, DEFAULT);

            assertThat(response.isAcknowledged(), is(true));
            assertThat(cluster, not(indexExists(indexName)));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES).withRestRequest(POST, "/_aliases")
        );
        auditLogsRule.assertExactly(
            1,
            grantedPrivilege(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES, "IndicesAliasesRequest")
        );
        auditLogsRule.assertExactly(
            1,
            auditPredicate(INDEX_EVENT).withEffectiveUser(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)
        );
    }

    @Test
    public void shouldDeleteIndexByAliasRequest_negative() throws IOException {
        String indexName = "delete_index_by_alias_request_negative";
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            IndicesAliasesRequest request = new IndicesAliasesRequest().addAliasAction(new AliasActions(REMOVE_INDEX).indices(indexName));

            assertThatThrownBy(() -> restHighLevelClient.indices().updateAliases(request, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/get"
    public void getIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("get_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            GetIndexRequest getIndexRequest = new GetIndexRequest(indexName);
            GetIndexResponse response = restHighLevelClient.indices().get(getIndexRequest, DEFAULT);

            assertThat(response, getIndexResponseContainsIndices(indexName));
        }
    }

    @Test
    public void getIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "get_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices().get(new GetIndexRequest(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices().get(new GetIndexRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> restHighLevelClient.indices().get(new GetIndexRequest("*"), DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/close", "indices:admin/close*"
    public void closeIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("close_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            CloseIndexRequest closeIndexRequest = new CloseIndexRequest(indexName);
            CloseIndexResponse response = restHighLevelClient.indices().close(closeIndexRequest, DEFAULT);

            assertThat(response, isSuccessfulCloseIndexResponse());
            assertThat(cluster, indexStateIsEqualTo(indexName, IndexMetadata.State.CLOSE));
        }
    }

    @Test
    public void closeIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "close_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices().close(new CloseIndexRequest(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .close(new CloseIndexRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> restHighLevelClient.indices().close(new CloseIndexRequest("*"), DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/open"
    public void openIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("open_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);
        IndexOperationsHelper.closeIndex(cluster, indexName);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            OpenIndexRequest closeIndexRequest = new OpenIndexRequest(indexName);
            OpenIndexResponse response = restHighLevelClient.indices().open(closeIndexRequest, DEFAULT);

            assertThat(response, isSuccessfulOpenIndexResponse());
            assertThat(cluster, indexStateIsEqualTo(indexName, IndexMetadata.State.OPEN));
        }
    }

    @Test
    public void openIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "open_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices().open(new OpenIndexRequest(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .open(new OpenIndexRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> restHighLevelClient.indices().open(new OpenIndexRequest("*"), DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/resize", "indices:monitor/stats
    public void shrinkIndex_positive() throws IOException {
        String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("shrink_index_positive_source");
        String targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("shrink_index_positive_target");
        Settings sourceIndexSettings = Settings.builder()
            .put("index.number_of_replicas", 1)
            .put("index.blocks.write", true)
            .put("index.number_of_shards", 4)
            .build();
        IndexOperationsHelper.createIndex(cluster, sourceIndexName, sourceIndexSettings);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ClusterHealthResponse healthResponse = restHighLevelClient.cluster()
                .health(
                    new ClusterHealthRequest(sourceIndexName).waitForNoRelocatingShards(true)
                        .waitForActiveShards(4)
                        .waitForNoInitializingShards(true)
                        .waitForGreenStatus(),
                    DEFAULT
                );

            assertThat(healthResponse.getStatus(), is(ClusterHealthStatus.GREEN));

            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);
            ResizeResponse response = restHighLevelClient.indices().shrink(resizeRequest, DEFAULT);

            assertThat(response, isSuccessfulResizeResponse(targetIndexName));
            assertThat(cluster, indexExists(targetIndexName));
        }
    }

    @Test
    public void shrinkIndex_negative() throws IOException {
        // user cannot access target index
        String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("shrink_index_negative_source");
        String targetIndexName = "shrink_index_negative_target";

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);

            assertThatThrownBy(() -> restHighLevelClient.indices().shrink(resizeRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }

        // user cannot access source index
        sourceIndexName = "shrink_index_negative_source";
        targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("shrink_index_negative_target");

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);

            assertThatThrownBy(() -> restHighLevelClient.indices().shrink(resizeRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }
    }

    @Test
    // required permissions: "indices:admin/resize", "indices:monitor/stats
    public void cloneIndex_positive() throws IOException {
        String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clone_index_positive_source");
        Settings sourceIndexSettings = Settings.builder().put("index.blocks.write", true).build();
        String targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clone_index_positive_target");
        IndexOperationsHelper.createIndex(cluster, sourceIndexName, sourceIndexSettings);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);
            ResizeResponse response = restHighLevelClient.indices().clone(resizeRequest, DEFAULT);

            assertThat(response, isSuccessfulResizeResponse(targetIndexName));
            assertThat(cluster, indexExists(targetIndexName));

            // can't clone the same index twice, target already exists
            ResizeRequest repeatResizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);
            assertThatThrownBy(() -> restHighLevelClient.indices().clone(repeatResizeRequest, DEFAULT), statusException(BAD_REQUEST));
        }
    }

    @Test
    public void cloneIndex_negative() throws IOException {
        // user cannot access target index
        String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clone_index_negative_source");
        String targetIndexName = "clone_index_negative_target";

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);

            assertThatThrownBy(() -> restHighLevelClient.indices().clone(resizeRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }

        // user cannot access source index
        sourceIndexName = "clone_index_negative_source";
        targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clone_index_negative_target");

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);

            assertThatThrownBy(() -> restHighLevelClient.indices().clone(resizeRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }
    }

    @Test
    // required permissions: "indices:admin/resize", "indices:monitor/stats
    public void splitIndex_positive() throws IOException {
        String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("split_index_positive_source");
        Settings sourceIndexSettings = Settings.builder().put("index.blocks.write", true).build();
        String targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("split_index_positive_target");
        IndexOperationsHelper.createIndex(cluster, sourceIndexName, sourceIndexSettings);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);
            resizeRequest.setSettings(Settings.builder().put("index.number_of_shards", 2).build());
            ResizeResponse response = restHighLevelClient.indices().split(resizeRequest, DEFAULT);

            assertThat(response, isSuccessfulResizeResponse(targetIndexName));
            assertThat(cluster, indexExists(targetIndexName));
        }
    }

    @Test
    public void splitIndex_negative() throws IOException {
        // user cannot access target index
        String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("split_index_negative_source");
        String targetIndexName = "split_index_negative_target";

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);
            resizeRequest.setSettings(Settings.builder().put("index.number_of_shards", 2).build());

            assertThatThrownBy(() -> restHighLevelClient.indices().split(resizeRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }

        // user cannot access source index
        sourceIndexName = "split_index_negative_source";
        targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("split_index_negative_target");

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ResizeRequest resizeRequest = new ResizeRequest(targetIndexName, sourceIndexName);
            resizeRequest.setSettings(Settings.builder().put("index.number_of_shards", 2).build());

            assertThatThrownBy(() -> restHighLevelClient.indices().split(resizeRequest, DEFAULT), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }
    }

    @Test
    // required permissions: "indices:monitor/settings/get"
    public void getIndexSettings_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("get_index_settings_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            GetSettingsRequest getSettingsRequest = new GetSettingsRequest().indices(indexName);
            GetSettingsResponse response = restHighLevelClient.indices().getSettings(getSettingsRequest, DEFAULT);

            assertThat(response, getSettingsResponseContainsIndices(indexName));
        }
    }

    @Test
    public void getIndexSettings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "get_index_settings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            assertThatThrownBy(
                () -> restHighLevelClient.indices().getSettings(new GetSettingsRequest().indices(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .getSettings(new GetSettingsRequest().indices(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices().getSettings(new GetSettingsRequest().indices("*"), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: "indices:admin/settings/update"
    public void updateIndexSettings_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("update_index_settings_positive");
        Settings initialSettings = Settings.builder().put("index.number_of_replicas", "2").build();
        Settings updatedSettings = Settings.builder().put("index.number_of_replicas", "4").build();
        IndexOperationsHelper.createIndex(cluster, indexName, initialSettings);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            UpdateSettingsRequest updateSettingsRequest = new UpdateSettingsRequest(indexName).settings(updatedSettings);
            var response = restHighLevelClient.indices().putSettings(updateSettingsRequest, DEFAULT);

            assertThat(response.isAcknowledged(), is(true));
            assertThat(cluster, indexSettingsContainValues(indexName, updatedSettings));
        }
    }

    @Test
    public void updateIndexSettings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "update_index_settings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        Settings settingsToUpdate = Settings.builder().put("index.number_of_replicas", 2).build();
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .putSettings(new UpdateSettingsRequest(indexThatUserHasNoAccessTo).settings(settingsToUpdate), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .putSettings(
                        new UpdateSettingsRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo).settings(settingsToUpdate),
                        DEFAULT
                    ),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices().putSettings(new UpdateSettingsRequest("*").settings(settingsToUpdate), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: indices:admin/mapping/put
    public void createIndexMappings_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("create_index_mappings_positive");
        Map<String, Object> indexMapping = Map.of("properties", Map.of("message", Map.of("type", "text")));
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            PutMappingRequest putMappingRequest = new PutMappingRequest(indexName).source(indexMapping);
            var response = restHighLevelClient.indices().putMapping(putMappingRequest, DEFAULT);

            assertThat(response.isAcknowledged(), is(true));
            assertThat(cluster, indexMappingIsEqualTo(indexName, indexMapping));
        }
    }

    @Test
    public void createIndexMappings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "create_index_mappings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        Map<String, Object> indexMapping = Map.of("properties", Map.of("message", Map.of("type", "text")));
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .putMapping(new PutMappingRequest(indexThatUserHasNoAccessTo).source(indexMapping), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .putMapping(new PutMappingRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo).source(indexMapping), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices().putMapping(new PutMappingRequest("*").source(indexMapping), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: indices:admin/mappings/get
    public void getIndexMappings_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("get_index_mappings_positive");
        Map<String, Object> indexMapping = Map.of("properties", Map.of("message", Map.of("type", "text")));
        IndexOperationsHelper.createIndex(cluster, indexName);
        IndexOperationsHelper.createMapping(cluster, indexName, indexMapping);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(indexName);
            GetMappingsResponse response = restHighLevelClient.indices().getMapping(getMappingsRequest, DEFAULT);

            assertThat(response, getMappingsResponseContainsIndices(indexName));
        }
    }

    @Test
    public void getIndexMappings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "get_index_mappings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices().getMapping(new GetMappingsRequest().indices(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .getMapping(new GetMappingsRequest().indices(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices().getMapping(new GetMappingsRequest().indices("*"), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: "indices:admin/cache/clear"
    public void clearIndexCache_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clear_index_cache_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            ClearIndicesCacheRequest clearIndicesCacheRequest = new ClearIndicesCacheRequest(indexName);
            ClearIndicesCacheResponse response = restHighLevelClient.indices().clearCache(clearIndicesCacheRequest, DEFAULT);

            assertThat(response, isSuccessfulClearIndicesCacheResponse());
        }
    }

    @Test
    public void clearIndexCache_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "clear_index_cache_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {

            assertThatThrownBy(
                () -> restHighLevelClient.indices().clearCache(new ClearIndicesCacheRequest(indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices()
                    .clearCache(new ClearIndicesCacheRequest(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo), DEFAULT),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> restHighLevelClient.indices().clearCache(new ClearIndicesCacheRequest("*"), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: "indices:admin/create", "indices:admin/aliases"
    public void shouldCreateIndexWithAlias_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("create_index_with_alias_positive");
        try (
            RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(
                USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES
            )
        ) {
            CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName).alias(
                new Alias(ALIAS_CREATE_INDEX_WITH_ALIAS_POSITIVE)
            );

            CreateIndexResponse createIndexResponse = restHighLevelClient.indices().create(createIndexRequest, DEFAULT);

            assertThat(createIndexResponse, isSuccessfulCreateIndexResponse(indexName));
            assertThat(cluster, indexExists(indexName));
            assertThat(internalClient, aliasExists(ALIAS_CREATE_INDEX_WITH_ALIAS_POSITIVE));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES).withRestRequest(
                PUT,
                "/index_operations_create_index_with_alias_positive"
            )
        );
        auditLogsRule.assertExactly(
            1,
            grantedPrivilege(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES, "CreateIndexRequest")
        );
        auditLogsRule.assertExactly(
            1,
            auditPredicate(INDEX_EVENT).withEffectiveUser(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)
        );
    }

    @Test
    public void shouldCreateIndexWithAlias_negative() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("create_index_with_alias_negative");
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(USER_ALLOWED_TO_CREATE_INDEX)) {
            CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName).alias(
                new Alias(ALIAS_CREATE_INDEX_WITH_ALIAS_NEGATIVE)
            );

            assertThatThrownBy(() -> restHighLevelClient.indices().create(createIndexRequest, DEFAULT), statusException(FORBIDDEN));

            assertThat(internalClient, not(aliasExists(ALIAS_CREATE_INDEX_WITH_ALIAS_NEGATIVE)));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(USER_ALLOWED_TO_CREATE_INDEX).withRestRequest(PUT, "/index_operations_create_index_with_alias_negative")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(USER_ALLOWED_TO_CREATE_INDEX, "CreateIndexRequest"));
    }
}
