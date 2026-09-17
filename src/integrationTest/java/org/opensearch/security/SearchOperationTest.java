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

import org.opensearch.action.admin.cluster.repositories.delete.DeleteRepositoryRequest;
import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.template.delete.DeleteIndexTemplateRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesResponse;
import org.opensearch.client.json.JsonData;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.HealthStatus;
import org.opensearch.client.opensearch._types.Refresh;
import org.opensearch.client.opensearch._types.mapping.Property;
import org.opensearch.client.opensearch.cluster.HealthRequest;
import org.opensearch.client.opensearch.cluster.HealthResponse;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.CountRequest;
import org.opensearch.client.opensearch.core.DeleteRequest;
import org.opensearch.client.opensearch.core.DeleteResponse;
import org.opensearch.client.opensearch.core.FieldCapsRequest;
import org.opensearch.client.opensearch.core.FieldCapsResponse;
import org.opensearch.client.opensearch.core.GetRequest;
import org.opensearch.client.opensearch.core.GetResponse;
import org.opensearch.client.opensearch.core.IndexRequest;
import org.opensearch.client.opensearch.core.MgetRequest;
import org.opensearch.client.opensearch.core.MgetResponse;
import org.opensearch.client.opensearch.core.MsearchRequest;
import org.opensearch.client.opensearch.core.MsearchResponse;
import org.opensearch.client.opensearch.core.ReindexRequest;
import org.opensearch.client.opensearch.core.ReindexResponse;
import org.opensearch.client.opensearch.core.ScrollRequest;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.UpdateRequest;
import org.opensearch.client.opensearch.core.UpdateResponse;
import org.opensearch.client.opensearch.indices.Alias;
import org.opensearch.client.opensearch.indices.ClearCacheRequest;
import org.opensearch.client.opensearch.indices.ClearCacheResponse;
import org.opensearch.client.opensearch.indices.CloneIndexRequest;
import org.opensearch.client.opensearch.indices.CloneIndexResponse;
import org.opensearch.client.opensearch.indices.CloseIndexRequest;
import org.opensearch.client.opensearch.indices.CloseIndexResponse;
import org.opensearch.client.opensearch.indices.CreateIndexRequest;
import org.opensearch.client.opensearch.indices.CreateIndexResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.DeleteTemplateRequest;
import org.opensearch.client.opensearch.indices.ExistsRequest;
import org.opensearch.client.opensearch.indices.GetIndexRequest;
import org.opensearch.client.opensearch.indices.GetIndexResponse;
import org.opensearch.client.opensearch.indices.GetIndicesSettingsRequest;
import org.opensearch.client.opensearch.indices.GetIndicesSettingsResponse;
import org.opensearch.client.opensearch.indices.GetMappingRequest;
import org.opensearch.client.opensearch.indices.GetMappingResponse;
import org.opensearch.client.opensearch.indices.IndexSettings;
import org.opensearch.client.opensearch.indices.OpenRequest;
import org.opensearch.client.opensearch.indices.OpenResponse;
import org.opensearch.client.opensearch.indices.PutIndicesSettingsRequest;
import org.opensearch.client.opensearch.indices.PutMappingRequest;
import org.opensearch.client.opensearch.indices.PutTemplateRequest;
import org.opensearch.client.opensearch.indices.ShrinkRequest;
import org.opensearch.client.opensearch.indices.ShrinkResponse;
import org.opensearch.client.opensearch.indices.SplitRequest;
import org.opensearch.client.opensearch.indices.SplitResponse;
import org.opensearch.client.opensearch.indices.UpdateAliasesRequest;
import org.opensearch.client.opensearch.indices.update_aliases.AddAction;
import org.opensearch.client.opensearch.indices.update_aliases.RemoveAction;
import org.opensearch.client.opensearch.indices.update_aliases.RemoveIndexAction;
import org.opensearch.client.opensearch.snapshot.CreateSnapshotResponse;
import org.opensearch.client.transport.endpoints.BooleanResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexTemplateMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.repositories.RepositoryMissingException;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.OpenSearchClientProvider.CloseableOpenSearchClient;
import org.opensearch.test.framework.matcher.client.GetResultMatchers;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.ClusterAdminClient;
import org.opensearch.transport.client.IndicesAdminClient;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.core.rest.RestStatus.BAD_REQUEST;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
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
import static org.opensearch.test.framework.client.SearchRequestFactory.averageAggregationRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.getSearchScrollRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.client.SearchRequestFactory.searchRequestWithScroll;
import static org.opensearch.test.framework.client.SearchRequestFactory.statsAggregationRequest;
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
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.client.BulkResponseMatchers.bulkResponseContainExceptions;
import static org.opensearch.test.framework.matcher.client.BulkResponseMatchers.failureBulkResponse;
import static org.opensearch.test.framework.matcher.client.BulkResponseMatchers.successBulkResponse;
import static org.opensearch.test.framework.matcher.client.DeleteResponseMatchers.isSuccessfulDeleteResponse;
import static org.opensearch.test.framework.matcher.client.ErrorCauseMatchers.errorType;
import static org.opensearch.test.framework.matcher.client.FieldCapsResponseMatchers.containsExactlyIndices;
import static org.opensearch.test.framework.matcher.client.FieldCapsResponseMatchers.containsFieldWithNameAndType;
import static org.opensearch.test.framework.matcher.client.FieldCapsResponseMatchers.numberOfFieldsIsEqualTo;
import static org.opensearch.test.framework.matcher.client.GetResponseMatchers.containDocument;
import static org.opensearch.test.framework.matcher.client.GetResponseMatchers.documentContainField;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.getIndexResponseContainsIndices;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.getMappingsResponseContainsIndices;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.getSettingsResponseContainsIndices;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.isSuccessfulClearIndicesCacheResponse;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.isSuccessfulCloneResponse;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.isSuccessfulCloseIndexResponse;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.isSuccessfulCreateIndexResponse;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.isSuccessfulOpenIndexResponse;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.isSuccessfulResizeResponse;
import static org.opensearch.test.framework.matcher.client.IndexResponseMatchers.isSuccessfulSplitResponse;
import static org.opensearch.test.framework.matcher.client.MultiGetResponseMatchers.isSuccessfulMultiGetResponse;
import static org.opensearch.test.framework.matcher.client.MultiGetResponseMatchers.numberOfGetItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.client.MultiSearchResponseMatchers.isSuccessfulMultiSearchResponse;
import static org.opensearch.test.framework.matcher.client.MultiSearchResponseMatchers.numberOfSearchItemResponsesIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.containAggregationWithNameAndType;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.containNotEmptyScrollingId;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.numberOfHitsInPageIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.searchHitsContainDocumentWithId;
import static org.opensearch.test.framework.matcher.client.TransportExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.client.UpdateResponseMatchers.isSuccessfulUpdateResponse;

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
            client.index(
                new org.opensearch.action.index.IndexRequest().setRefreshPolicy(IMMEDIATE)
                    .index(SONG_INDEX_NAME)
                    .id(ID_S2)
                    .source(SONGS[1].asMap())
            ).actionGet();
            client.index(
                new org.opensearch.action.index.IndexRequest().setRefreshPolicy(IMMEDIATE)
                    .index(SONG_INDEX_NAME)
                    .id(ID_S3)
                    .source(SONGS[2].asMap())
            ).actionGet();

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
            createTemplateRequest.alias(new org.opensearch.action.admin.indices.alias.Alias(ALIAS_FROM_UNDELETABLE_TEMPLATE));
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
                org.opensearch.action.admin.indices.delete.DeleteIndexRequest deleteIndexRequest =
                    new org.opensearch.action.admin.indices.delete.DeleteIndexRequest(indexToBeDeleted);
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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(SONG_INDEX_NAME, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(PROHIBITED_SONG_INDEX_NAME, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldSearchForDocumentsViaAlias_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(SONG_LYRICS_ALIAS, QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(PROHIBITED_SONG_ALIAS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics_index_alias/_search")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAbleToSearchSongViaMultiIndexAlias_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(DOUBLE_READER_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(COLLECTIVE_INDEX_ALIAS, QUERY_TITLE_NEXT_SONG);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(COLLECTIVE_INDEX_ALIAS, QUERY_TITLE_POISON);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/collective-index-alias/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAbleToSearchAllIndexes_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(ADMIN_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(QUERY_TITLE_MAGNUM_OPUS);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAbleToSearchSongIndexesWithAsterisk_prohibitedSongIndex_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(DOUBLE_READER_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("*" + SONG_INDEX_NAME, QUERY_TITLE_POISON);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(DOUBLE_READER_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("*" + SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("*" + SONG_INDEX_NAME, QUERY_TITLE_NEXT_SONG);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/*song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldFindSongUsingDslQuery_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = SearchRequest.of(
                r -> r.index(SONG_INDEX_NAME)
                    .query(
                        org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.bool()
                            .filter(
                                org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.regexp()
                                    .field(FIELD_ARTIST)
                                    .value("f.+")
                                    .build()
                                    .toQuery()
                            )
                            .filter(
                                org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.match()
                                    .field(FIELD_TITLE)
                                    .query(FieldValue.of(TITLE_MAGNUM_OPUS))
                                    .build()
                                    .toQuery()
                            )
                            .build()
                            .toQuery()
                    )
            );
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = SearchRequest.of(
                r -> r.index(PROHIBITED_SONG_INDEX_NAME)
                    .query(
                        org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.bool()
                            .filter(
                                org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.regexp()
                                    .field(FIELD_ARTIST)
                                    .value("n.+")
                                    .build()
                                    .toQuery()
                            )
                            .filter(
                                org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.match()
                                    .field(FIELD_TITLE)
                                    .query(FieldValue.of(TITLE_POISON))
                                    .build()
                                    .toQuery()
                            )
                            .build()
                            .toQuery()
                    )
            );

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldPerformSearchWithAllIndexAlias_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(ADMIN_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest("_all", QUERY_TITLE_MAGNUM_OPUS);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_all/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldScrollOverSearchResults_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(SONG_INDEX_NAME, 2);
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
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_search/scroll"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchScrollRequest"));
    }

    @Test
    public void shouldScrollOverSearchResults_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(DOUBLE_READER_USER)) {
            SearchRequest searchRequest = searchRequestWithScroll(SONG_INDEX_NAME, 2);
            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);
            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containNotEmptyScrollingId());

            ScrollRequest scrollRequest = getSearchScrollRequest(searchResponse);

            assertThatThrownBy(() -> client.scroll(scrollRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(DOUBLE_READER_USER, "SearchRequest"));
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/_search/scroll"));
        auditLogsRule.assertExactlyOne(missingPrivilege(DOUBLE_READER_USER, "SearchScrollRequest"));
    }

    @Test
    public void shouldGetDocument_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            GetResponse<?> response = client.get(GetRequest.of(r -> r.index(SONG_INDEX_NAME).id(ID_S1)), Map.class);

            assertThat(response, containDocument(SONG_INDEX_NAME, ID_S1));
            assertThat(response, documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/song_lyrics/_doc/1"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "GetRequest"));
    }

    @Test
    public void shouldGetDocument_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            GetRequest getRequest = GetRequest.of(r -> r.index(PROHIBITED_SONG_INDEX_NAME).id(ID_P4));
            assertThatThrownBy(() -> client.get(getRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/prohibited_song_lyrics/_doc/4"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "GetRequest"));
    }

    @Test
    public void shouldPerformMultiGetDocuments_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            MgetRequest request = MgetRequest.of(r -> r.index(SONG_INDEX_NAME).ids(ID_S1, ID_S2));

            MgetResponse<?> response = client.mget(request, Map.class);

            assertThat(response, is(notNullValue()));
            assertThat(response, isSuccessfulMultiGetResponse());
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            var responses = response.docs();
            assertThat(
                responses.get(0).result(),
                allOf(
                    GetResultMatchers.containDocument(SONG_INDEX_NAME, ID_S1),
                    GetResultMatchers.documentContainField(FIELD_TITLE, TITLE_MAGNUM_OPUS)
                )
            );
            assertThat(
                responses.get(1).result(),
                allOf(
                    GetResultMatchers.containDocument(SONG_INDEX_NAME, ID_S2),
                    GetResultMatchers.documentContainField(FIELD_TITLE, TITLE_SONG_1_PLUS_1)
                )
            );
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_mget"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetShardRequest"));
    }

    @Test
    public void shouldPerformMultiGetDocuments_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(DOUBLE_READER_USER)) {
            MgetRequest request = MgetRequest.of(r -> r.index(SONG_INDEX_NAME).ids(ID_S1));

            assertThatThrownBy(() -> client.mget(request, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/song_lyrics/_mget"));
        auditLogsRule.assertExactlyOne(missingPrivilege(DOUBLE_READER_USER, "MultiGetRequest"));
    }

    @Test
    public void shouldPerformMultiGetDocuments_partiallyPositive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            MgetRequest request = MgetRequest.of(
                r -> r.docs(d -> d.index(SONG_INDEX_NAME).id(ID_S1)).docs(d -> d.index(PROHIBITED_SONG_INDEX_NAME).id(ID_P4))
            );

            MgetResponse<?> response = client.mget(request, Map.class);

            assertThat(request, notNullValue());
            assertThat(response, not(isSuccessfulMultiGetResponse()));
            assertThat(response, numberOfGetItemResponsesIsEqualTo(2));

            var responses = response.docs();
            // assertThat(responses, arrayContaining(hasProperty("failure", nullValue()), hasProperty("failure", notNullValue())));
            assertThat(responses.get(1).failure().error().type(), equalTo("security_exception"));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_mget"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiGetShardRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "MultiGetShardRequest").withIndex(PROHIBITED_SONG_INDEX_NAME));
    }

    @Test
    public void shouldBeAllowedToPerformMulitSearch_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            MsearchRequest request = MsearchRequest.of(
                r -> r.searches(
                    s -> s.header(h -> h.index(SONG_INDEX_NAME))
                        .body(
                            b -> b.query(
                                org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.queryString()
                                    .query(QUERY_TITLE_MAGNUM_OPUS)
                                    .build()
                                    .toQuery()
                            )
                        )
                )
                    .searches(
                        s -> s.header(h -> h.index(SONG_INDEX_NAME))
                            .body(
                                b -> b.query(
                                    org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.queryString()
                                        .query(QUERY_TITLE_NEXT_SONG)
                                        .build()
                                        .toQuery()
                                )
                            )
                    )
            );

            MsearchResponse<?> response = client.msearch(request, Map.class);

            assertThat(response, notNullValue());
            assertThat(response, isSuccessfulMultiSearchResponse());
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            var responses = response.responses();

            assertThat(responses.get(0).result(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(responses.get(0).result(), searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S1));
            assertThat(responses.get(1).result(), searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_NEXT_SONG));
            assertThat(responses.get(1).result(), searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, ID_S3));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_msearch"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiSearchRequest"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldBeAllowedToPerformMulitSearch_partiallyPositive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            MsearchRequest request = MsearchRequest.of(
                r -> r.searches(
                    s -> s.header(h -> h.index(SONG_INDEX_NAME))
                        .body(
                            b -> b.query(
                                org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.queryString()
                                    .query(QUERY_TITLE_MAGNUM_OPUS)
                                    .build()
                                    .toQuery()
                            )
                        )
                )
                    .searches(
                        s -> s.header(h -> h.index(PROHIBITED_SONG_INDEX_NAME))
                            .body(
                                b -> b.query(
                                    org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.queryString()
                                        .query(QUERY_TITLE_POISON)
                                        .build()
                                        .toQuery()
                                )
                            )
                    )
            );

            MsearchResponse<?> response = client.msearch(request, Map.class);

            assertThat(response, notNullValue());
            assertThat(response, not(isSuccessfulMultiSearchResponse()));
            assertThat(response, numberOfSearchItemResponsesIsEqualTo(2));

            var responses = response.responses();
            assertThat(responses.get(0).isFailure(), equalTo(false));
            assertThat(responses.get(1).isFailure(), equalTo(true));
            assertThat(responses.get(1).failure().error().type(), containsString("security_exception"));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_msearch"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "MultiSearchRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(PROHIBITED_SONG_INDEX_NAME));
    }

    @Test
    public void shouldBeAllowedToPerformMulitSearch_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(DOUBLE_READER_USER)) {

            MsearchRequest request = MsearchRequest.of(
                r -> r.searches(
                    s -> s.header(h -> h.index(SONG_INDEX_NAME))
                        .body(
                            b -> b.query(
                                org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.queryString()
                                    .query(QUERY_TITLE_MAGNUM_OPUS)
                                    .build()
                                    .toQuery()
                            )
                        )
                )
                    .searches(
                        s -> s.header(h -> h.index(SONG_INDEX_NAME))
                            .body(
                                b -> b.query(
                                    org.opensearch.client.opensearch._types.query_dsl.QueryBuilders.queryString()
                                        .query(QUERY_TITLE_NEXT_SONG)
                                        .build()
                                        .toQuery()
                                )
                            )
                    )
            );

            assertThatThrownBy(() -> client.msearch(request, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(DOUBLE_READER_USER).withRestRequest(POST, "/_msearch"));
        auditLogsRule.assertAtLeast(1, missingPrivilege(DOUBLE_READER_USER, "MultiSearchRequest"));
    }

    @Test
    public void shouldAggregateDataAndComputeAverage_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            final String aggregationName = "averageStars";
            SearchRequest searchRequest = averageAggregationRequest(SONG_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "avg"));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(SONG_INDEX_NAME));
    }

    @Test
    public void shouldAggregateDataAndComputeAverage_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = averageAggregationRequest(PROHIBITED_SONG_INDEX_NAME, "averageStars", FIELD_STARS);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest").withIndex(PROHIBITED_SONG_INDEX_NAME));
    }

    @Test
    public void shouldPerformStatAggregation_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            final String aggregationName = "statsStars";
            SearchRequest searchRequest = statsAggregationRequest(SONG_INDEX_NAME, aggregationName, FIELD_STARS);

            SearchResponse<?> searchResponse = client.search(searchRequest, Map.class);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, containAggregationWithNameAndType(aggregationName, "stats"));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldPerformStatAggregation_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SearchRequest searchRequest = statsAggregationRequest(PROHIBITED_SONG_INDEX_NAME, "statsStars", FIELD_STARS);

            assertThatThrownBy(() -> client.search(searchRequest, Map.class), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/prohibited_song_lyrics/_search"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "SearchRequest"));
    }

    @Test
    public void shouldIndexDocumentInBulkRequest_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {

            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("one").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("two").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

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
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertAtLeast(1, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldIndexDocumentInBulkRequest_partiallyPositive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(SONG_INDEX_NAME).id("one").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("two").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

            assertThat(response, bulkResponseContainExceptions(0, errorType(equalTo("security_exception"))));
            assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, "two"));
            assertThat(
                internalClient,
                clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, TITLE_SONG_1_PLUS_1)
            );
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertAtLeast(2, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldIndexDocumentInBulkRequest_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(SONG_INDEX_NAME).id("one").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(SONG_INDEX_NAME).id("two").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

            assertThat(response, allOf(failureBulkResponse(), bulkResponseContainExceptions(errorType(equalTo("security_exception")))));
            assertThat(internalClient, not(clusterContainsDocument(SONG_INDEX_NAME, "one")));
            assertThat(internalClient, not(clusterContainsDocument(SONG_INDEX_NAME, "two")));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest").withIndex(SONG_INDEX_NAME));
    }

    @Test
    public void shouldUpdateDocumentsInBulk_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            final String titleOne = "shape of my mind";
            final String titleTwo = "forgiven";

            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("one").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("two").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );
            client.bulk(bulkRequest);

            bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.update(i -> i.index(WRITE_SONG_INDEX_NAME).id("one").document(Map.of(FIELD_TITLE, titleOne))))
                    .operations(op -> op.update(i -> i.index(WRITE_SONG_INDEX_NAME).id("two").document(Map.of(FIELD_TITLE, titleTwo))))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

            assertThat(response, successBulkResponse());
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, titleOne));
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "two", FIELD_TITLE, titleTwo));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
        auditLogsRule.assertAtLeast(1, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
    }

    @Test
    public void shouldUpdateDocumentsInBulk_partiallyPositive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            final String titleOne = "shape of my mind";
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("one").document(SONGS[0].asMap())))
                    .refresh(Refresh.True)
            );
            client.bulk(bulkRequest);

            bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.update(i -> i.index(WRITE_SONG_INDEX_NAME).id("one").document(Map.of(FIELD_TITLE, titleOne))))
                    .operations(op -> op.update(i -> i.index(SONG_INDEX_NAME).id(ID_S2).document(Map.of(FIELD_TITLE, "forgiven"))))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

            assertThat(response, bulkResponseContainExceptions(1, errorType(equalTo("security_exception"))));
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(WRITE_SONG_INDEX_NAME, "one", FIELD_TITLE, titleOne));
            assertThat(internalClient, clusterContainsDocumentWithFieldValue(SONG_INDEX_NAME, ID_S2, FIELD_TITLE, TITLE_SONG_1_PLUS_1));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactly(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertAtLeast(1, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeast(1, missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest").withIndex(SONG_INDEX_NAME));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldUpdateDocumentsInBulk_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(
                    op -> op.update(i -> i.index(SONG_INDEX_NAME).id(ID_S1).document(Map.of(FIELD_TITLE, "shape of my mind")))
                )
                    .operations(op -> op.update(i -> i.index(SONG_INDEX_NAME).id(ID_S2).document(Map.of(FIELD_TITLE, "forgiven"))))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

            assertThat(response, allOf(failureBulkResponse(), bulkResponseContainExceptions(errorType(equalTo("security_exception")))));
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

        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("one").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("two").document(SONGS[1].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("three").document(SONGS[2].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("four").document(SONGS[3].asMap())))
                    .refresh(Refresh.True)
            );
            assertThat(client.bulk(bulkRequest), successBulkResponse());

            bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.delete(i -> i.index(WRITE_SONG_INDEX_NAME).id("one")))
                    .operations(op -> op.delete(i -> i.index(WRITE_SONG_INDEX_NAME).id("three")))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

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
        auditLogsRule.assertAtLeast(2, auditPredicate(null).withLayer(AuditLog.Origin.TRANSPORT));
        auditLogsRule.assertAtLeast(4, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
        auditLogsRule.assertAtLeast(4, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
    }

    @Test
    public void shouldDeleteDocumentInBulk_partiallyPositive() throws IOException {
        Settings indexSettings = Settings.builder().put("index.number_of_replicas", 0).put("index.number_of_shards", 1).build();
        IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);

        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("one").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("two").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );
            assertThat(client.bulk(bulkRequest), successBulkResponse());

            bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.delete(i -> i.index(WRITE_SONG_INDEX_NAME).id("one")))
                    .operations(op -> op.delete(i -> i.index(SONG_INDEX_NAME).id(ID_S3)))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);
            assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, "one")));

            assertThat(response, bulkResponseContainExceptions(1, errorType(equalTo(("security_exception")))));
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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.delete(i -> i.index(SONG_INDEX_NAME).id(ID_S1)))
                    .operations(op -> op.delete(i -> i.index(SONG_INDEX_NAME).id(ID_S3)))
                    .refresh(Refresh.True)
            );

            BulkResponse response = client.bulk(bulkRequest);

            assertThat(response, allOf(failureBulkResponse(), bulkResponseContainExceptions(errorType(equalTo(("security_exception"))))));
            assertThat(internalClient, clusterContainsDocument(SONG_INDEX_NAME, ID_S1));
            assertThat(internalClient, clusterContainsDocument(SONG_INDEX_NAME, ID_S3));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(POST, "/_bulk"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_WRITE_USER, "BulkShardRequest"));

    }

    @Test
    public void shouldReindexDocuments_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(REINDEXING_USER)) {
            ReindexRequest reindexRequest = ReindexRequest.of(
                r -> r.source(s -> s.index(SONG_INDEX_NAME)).dest(d -> d.index(WRITE_SONG_INDEX_NAME))
            );

            ReindexResponse response = client.reindex(reindexRequest);

            assertThat(response, notNullValue());
            assertThat(response.failures(), empty());
            assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_S1));
            assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_S2));
            assertThat(internalClient, clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_S3));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(REINDEXING_USER).withRestRequest(POST, "/_reindex"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "ReindexRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "SearchRequest"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(REINDEXING_USER, "CreateIndexRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(REINDEXING_USER, "SearchScrollRequest"));
        auditLogsRule.assertAtLeast(1, auditPredicate(INDEX_EVENT).withEffectiveUser(REINDEXING_USER));
        auditLogsRule.assertAtLeast(1, missingPrivilege(REINDEXING_USER, "ClearScrollRequest"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(REINDEXING_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldReindexDocuments_negativeSource() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(REINDEXING_USER)) {
            ReindexRequest reindexRequest = ReindexRequest.of(
                r -> r.source(s -> s.index(PROHIBITED_SONG_INDEX_NAME)).dest(d -> d.index(WRITE_SONG_INDEX_NAME))
            );

            assertThatThrownBy(() -> client.reindex(reindexRequest), statusException(FORBIDDEN));
            assertThat(internalClient, not(clusterContainsDocument(WRITE_SONG_INDEX_NAME, ID_P4)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(REINDEXING_USER).withRestRequest(POST, "/_reindex"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "ReindexRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(REINDEXING_USER, "SearchRequest"));
    }

    @Test
    public void shouldReindexDocuments_negativeDestination() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(REINDEXING_USER)) {
            ReindexRequest reindexRequest = ReindexRequest.of(
                r -> r.source(s -> s.index(SONG_INDEX_NAME)).dest(d -> d.index(PROHIBITED_SONG_INDEX_NAME))
            );

            assertThatThrownBy(() -> client.reindex(reindexRequest), statusException(FORBIDDEN));
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
        try (CloseableOpenSearchClient client = cluster.getClient(REINDEXING_USER)) {
            ReindexRequest reindexRequest = ReindexRequest.of(
                r -> r.source(s -> s.index(PROHIBITED_SONG_INDEX_NAME)).dest(d -> d.index(SONG_INDEX_NAME))
            );

            assertThatThrownBy(() -> client.reindex(reindexRequest), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(REINDEXING_USER).withRestRequest(POST, "/_reindex"));
        auditLogsRule.assertExactlyOne(grantedPrivilege(REINDEXING_USER, "ReindexRequest"));
        auditLogsRule.assertExactlyOne(missingPrivilege(REINDEXING_USER, "SearchRequest"));
    }

    @Test
    public void shouldUpdateDocument_positive() throws IOException {
        String newField = "newField";
        String newValue = "newValue";
        try (CloseableOpenSearchClient client = cluster.getClient(UPDATE_DELETE_USER)) {
            UpdateRequest<Map, ?> updateRequest = UpdateRequest.of(
                r -> r.index(UPDATE_DELETE_OPERATION_INDEX_NAME)
                    .id(DOCUMENT_TO_UPDATE_ID)
                    .doc(Map.of(newField, newValue))
                    .refresh(Refresh.True)
            );

            UpdateResponse<?> response = client.update(updateRequest, Map.class);

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
        try (CloseableOpenSearchClient client = cluster.getClient(UPDATE_DELETE_USER)) {
            UpdateRequest<Map, ?> updateRequest = UpdateRequest.of(
                r -> r.index(PROHIBITED_SONG_INDEX_NAME).id(DOCUMENT_TO_UPDATE_ID).doc(Map.of(newField, newValue)).refresh(Refresh.True)
            );
            assertThatThrownBy(() -> client.update(updateRequest, Map.class), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldDeleteDocument_positive() throws IOException {
        String docId = "shouldDeleteDocument_positive";
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(
                new org.opensearch.action.index.IndexRequest(UPDATE_DELETE_OPERATION_INDEX_NAME).id(docId)
                    .source("field", "value")
                    .setRefreshPolicy(IMMEDIATE)
            ).actionGet();
            assertThat(internalClient, clusterContainsDocument(UPDATE_DELETE_OPERATION_INDEX_NAME, docId));
        }
        try (CloseableOpenSearchClient client = cluster.getClient(UPDATE_DELETE_USER)) {
            DeleteRequest deleteRequest = DeleteRequest.of(
                r -> r.index(UPDATE_DELETE_OPERATION_INDEX_NAME).id(docId).refresh(Refresh.True)
            );

            DeleteResponse response = client.delete(deleteRequest);

            assertThat(response, isSuccessfulDeleteResponse());
            assertThat(internalClient, not(clusterContainsDocument(UPDATE_DELETE_OPERATION_INDEX_NAME, docId)));
        }
    }

    @Test
    public void shouldDeleteDocument_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(UPDATE_DELETE_USER)) {
            DeleteRequest deleteRequest = DeleteRequest.of(r -> r.index(PROHIBITED_SONG_INDEX_NAME).id(ID_S1).refresh(Refresh.True));

            assertThatThrownBy(() -> client.delete(deleteRequest), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldCreateAlias_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            UpdateAliasesRequest indicesAliasesRequest = UpdateAliasesRequest.of(
                r -> r.actions(a -> a.add(AddAction.of(add -> add.index(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME))))
            );

            var response = client.indices().updateAliases(indicesAliasesRequest);

            assertThat(response, notNullValue());
            assertThat(response.acknowledged(), equalTo(true));
            assertThat(internalClient, clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_S1));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
        auditLogsRule.assertAtLeast(1, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_READ_USER));
    }

    @Test
    public void shouldCreateAlias_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            UpdateAliasesRequest indicesAliasesRequest = UpdateAliasesRequest.of(
                r -> r.actions(a -> a.add(AddAction.of(add -> add.index(PROHIBITED_SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME))))
            );

            assertThatThrownBy(() -> client.indices().updateAliases(indicesAliasesRequest), statusException(FORBIDDEN));

            assertThat(internalClient, not(clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_P4)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
    }

    @Test
    public void shouldDeleteAlias_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            UpdateAliasesRequest indicesAliasesRequest = UpdateAliasesRequest.of(
                r -> r.actions(a -> a.add(AddAction.of(add -> add.index(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME))))
            );

            client.indices().updateAliases(indicesAliasesRequest);
            indicesAliasesRequest = UpdateAliasesRequest.of(
                r -> r.actions(a -> a.remove(RemoveAction.of(add -> add.index(SONG_INDEX_NAME).alias(TEMPORARY_ALIAS_NAME))))
            );

            var response = client.indices().updateAliases(indicesAliasesRequest);

            assertThat(response, notNullValue());
            assertThat(response.acknowledged(), equalTo(true));
            assertThat(internalClient, not(clusterContainsDocument(TEMPORARY_ALIAS_NAME, ID_S1)));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
        auditLogsRule.assertAtLeast(2, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_READ_USER));
    }

    @Test
    public void shouldDeleteAlias_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            UpdateAliasesRequest indicesAliasesRequest = UpdateAliasesRequest.of(
                r -> r.actions(a -> a.remove(RemoveAction.of(add -> add.index(PROHIBITED_SONG_INDEX_NAME).alias(PROHIBITED_SONG_ALIAS))))
            );

            assertThatThrownBy(() -> client.indices().updateAliases(indicesAliasesRequest), statusException(FORBIDDEN));

            assertThat(internalClient, clusterContainsDocument(PROHIBITED_SONG_INDEX_NAME, ID_P4));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(POST, "/_aliases"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "IndicesAliasesRequest"));
    }

    @Test
    public void shouldCreateIndexTemplate_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            PutTemplateRequest request = PutTemplateRequest.of(
                r -> r.name(MUSICAL_INDEX_TEMPLATE)
                    .indexPatterns(TEMPLATE_INDEX_PREFIX)
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, Alias.builder().build())
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, Alias.builder().build())
            );

            var response = client.indices().putTemplate(request);

            assertThat(response, notNullValue());
            assertThat(response.acknowledged(), equalTo(true));
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
            String documentId = "0001";
            IndexRequest<?> indexRequest = IndexRequest.of(
                r -> r.index(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ).id(documentId).document(SONGS[0].asMap()).refresh(Refresh.True)
            );
            client.index(indexRequest);
            assertThat(internalClient, clusterContainsDocument(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ, documentId));
            assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, documentId));
            assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, documentId));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/song-transcription-jazz/_doc/0001"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutIndexTemplateRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "IndexRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertAtLeast(2, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldCreateIndexTemplate_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            PutTemplateRequest request = PutTemplateRequest.of(
                r -> r.name(MUSICAL_INDEX_TEMPLATE)
                    .indexPatterns(TEMPLATE_INDEX_PREFIX)
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, Alias.builder().build())
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, Alias.builder().build())
            );

            assertThatThrownBy(() -> client.indices().putTemplate(request), statusException(FORBIDDEN));
            assertThat(internalClient, not(clusterContainTemplate(MUSICAL_INDEX_TEMPLATE)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "PutIndexTemplateRequest"));
    }

    @Test
    public void shouldDeleteTemplate_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            PutTemplateRequest request = PutTemplateRequest.of(r -> r.name(MUSICAL_INDEX_TEMPLATE).indexPatterns(TEMPLATE_INDEX_PREFIX));

            client.indices().putTemplate(request);
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
            DeleteTemplateRequest deleteRequest = DeleteTemplateRequest.of(r -> r.name(MUSICAL_INDEX_TEMPLATE));

            var response = client.indices().deleteTemplate(deleteRequest);

            assertThat(response, notNullValue());
            assertThat(response.acknowledged(), equalTo(true));
            assertThat(internalClient, not(clusterContainTemplate(MUSICAL_INDEX_TEMPLATE)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(DELETE, "/_template/musical-index-template"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutIndexTemplateRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "DeleteIndexTemplateRequest"));
        auditLogsRule.assertAtLeast(2, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
    }

    @Test
    public void shouldDeleteTemplate_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            DeleteTemplateRequest deleteRequest = DeleteTemplateRequest.of(r -> r.name(UNDELETABLE_TEMPLATE_NAME));

            assertThatThrownBy(() -> client.indices().deleteTemplate(deleteRequest), statusException(FORBIDDEN));

            assertThat(internalClient, clusterContainTemplate(UNDELETABLE_TEMPLATE_NAME));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_READ_USER).withRestRequest(DELETE, "/_template/undeletable-template-name")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "DeleteIndexTemplateRequest"));
    }

    @Test
    public void shouldUpdateTemplate_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            PutTemplateRequest request = PutTemplateRequest.of(
                r -> r.name(MUSICAL_INDEX_TEMPLATE)
                    .indexPatterns(TEMPLATE_INDEX_PREFIX)
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, Alias.builder().build())
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, Alias.builder().build())
            );

            client.indices().putTemplate(request);
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));

            request = PutTemplateRequest.of(
                r -> r.name(MUSICAL_INDEX_TEMPLATE)
                    .indexPatterns(TEMPLATE_INDEX_PREFIX)
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003, Alias.builder().build())
            );

            var response = client.indices().putTemplate(request);

            assertThat(response, notNullValue());
            assertThat(response.acknowledged(), equalTo(true));
            String documentId = "000one";
            IndexRequest<?> indexRequest = IndexRequest.of(
                r -> r.index(INDEX_NAME_SONG_TRANSCRIPTION_JAZZ).id(documentId).document(SONGS[0].asMap()).refresh(Refresh.True)
            );

            client.index(indexRequest);
            assertThat(internalClient, clusterContainTemplate(MUSICAL_INDEX_TEMPLATE));
            assertThat(internalClient, clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003, documentId));
            assertThat(internalClient, not(clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0001, documentId)));
            assertThat(internalClient, not(clusterContainsDocument(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0002, documentId)));
        }
        auditLogsRule.assertExactly(2, userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_template/musical-index-template"));
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/song-transcription-jazz/_doc/000one"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutIndexTemplateRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "IndexRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateIndexRequest"));
        auditLogsRule.assertAtLeast(3, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldUpdateTemplate_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            PutTemplateRequest request = PutTemplateRequest.of(
                r -> r.name(UNDELETABLE_TEMPLATE_NAME)
                    .indexPatterns(TEMPLATE_INDEX_PREFIX)
                    .aliases(ALIAS_USED_IN_MUSICAL_INDEX_TEMPLATE_0003, Alias.builder().build())
            );

            assertThatThrownBy(() -> client.indices().putTemplate(request), statusException(FORBIDDEN));
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
        try (CloseableOpenSearchClient client = cluster.getClient(ADMIN_USER)) {
            FieldCapsRequest request = FieldCapsRequest.of(r -> r.fields(FIELD_TITLE));

            FieldCapsResponse response = client.fieldCaps(request);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            FieldCapsRequest request = FieldCapsRequest.of(r -> r.fields(FIELD_TITLE));

            assertThatThrownBy(() -> client.fieldCaps(request), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/_field_caps"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "FieldCapabilitiesRequest"));
    }

    @Test
    public void shouldGetFieldCapabilitiesForParticularIndex_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            FieldCapsRequest request = FieldCapsRequest.of(r -> r.index(SONG_INDEX_NAME).fields(FIELD_TITLE));

            FieldCapsResponse response = client.fieldCaps(request);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            FieldCapsRequest request = FieldCapsRequest.of(r -> r.index(PROHIBITED_SONG_INDEX_NAME).fields(FIELD_TITLE));

            assertThatThrownBy(() -> client.fieldCaps(request), statusException(FORBIDDEN));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_READ_USER).withRestRequest(GET, "/prohibited_song_lyrics/_field_caps"));
        auditLogsRule.assertExactlyOne(missingPrivilege(LIMITED_READ_USER, "FieldCapabilitiesRequest"));
    }

    @Test
    public void shouldCreateSnapshotRepository_positive() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
            String snapshotDirPath = cluster.getSnapshotDirPath();

            var response = steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotDirPath, "fs");

            assertThat(response, notNullValue());
            assertThat(response.acknowledged(), equalTo(true));
            assertThat(internalClient, clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
    }

    @Test
    public void shouldCreateSnapshotRepository_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
            assertThat(internalClient, clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME));

            var response = steps.deleteSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME);

            assertThat(response, notNullValue());
            assertThat(response.acknowledged(), equalTo(true));
            assertThat(internalClient, not(clusterContainsSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME)));
        }
        auditLogsRule.assertExactlyOne(userAuthenticated(LIMITED_WRITE_USER).withRestRequest(PUT, "/_snapshot/test-snapshot-repository"));
        auditLogsRule.assertExactlyOne(
            userAuthenticated(LIMITED_WRITE_USER).withRestRequest(DELETE, "/_snapshot/test-snapshot-repository")
        );
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "DeleteRepositoryRequest"));
    }

    @Test
    public void shouldDeleteSnapshotRepository_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

            CreateSnapshotResponse response = steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);

            assertThat(response, notNullValue());
            assertThat(response.accepted(), equalTo(true));
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
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertAtLeast(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
    }

    @Test
    public void shouldCreateSnapshot_negative() throws IOException {
        final String snapshotName = "snapshot-negative-test";
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);

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
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
            client.snapshot();
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

            var response = steps.deleteSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

            assertThat(response.acknowledged(), equalTo(true));
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
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "DeleteSnapshotRequest"));
        auditLogsRule.assertAtLeast(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
    }

    @Test
    public void shouldDeleteSnapshot_negative() throws IOException {
        String snapshotName = "delete-snapshot-negative";
        long snapshotGetCount;
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, SONG_INDEX_NAME);
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
        }
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
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
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertAtLeast(1, missingPrivilege(LIMITED_READ_USER, "DeleteSnapshotRequest"));
        auditLogsRule.assertAtLeast(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
    }

    @Test
    public void shouldRestoreSnapshot_positive() throws IOException {
        final String snapshotName = "restore-snapshot-positive";
        long snapshotGetCount;
        AtomicInteger restoredCount = new AtomicInteger();
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
            // 1. create some documents
            Settings indexSettings = Settings.builder().put("index.number_of_replicas", 0).put("index.number_of_shards", 1).build();
            IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);

            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Eins").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Zwei").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );

            client.bulk(bulkRequest);

            // 2. create snapshot repository
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

            // 3. create snapshot
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME);

            // 4. wait till snapshot is ready
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);

            // 5. introduce some changes
            bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Drei").document(SONGS[2].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Vier").document(SONGS[3].asMap())))
                    .operations(op -> op.delete(i -> i.index(WRITE_SONG_INDEX_NAME).id("Eins")))
                    .refresh(Refresh.True)
            );
            client.bulk(bulkRequest);

            // 6. restore the snapshot
            var response = steps.restoreSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, "(.+)", "restored_$1");

            assertThat(response, notNullValue());
            assertThat(response.accepted(), equalTo(true));

            // 7. wait until snapshot is restored
            CountRequest countRequest = CountRequest.of(r -> r.index(RESTORED_SONG_INDEX_NAME));
            Awaitility.await()
                .ignoreExceptions()
                .pollInterval(100, TimeUnit.MILLISECONDS)
                .alias("Index contains proper number of documents restored from snapshot.")
                .until(() -> {
                    restoredCount.incrementAndGet();
                    return client.count(countRequest).count() == 2;
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
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "RestoreSnapshotRequest"));
        auditLogsRule.assertAtLeast(restoredCount.get(), grantedPrivilege(LIMITED_WRITE_USER, "SearchRequest"));
        auditLogsRule.assertAtLeast(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldRestoreSnapshot_failureForbiddenIndex() throws IOException {
        final String snapshotName = "restore-snapshot-negative-forbidden-index";
        String restoreToIndex = "forbidden_index";
        long snapshotGetCount;
        Settings indexSettings = Settings.builder().put("index.number_of_shards", 1).put("index.number_of_replicas", 0).build();
        IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {

            SnapshotSteps steps = new SnapshotSteps(client);
            // 1. create some documents
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Eins").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Zwei").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );
            client.bulk(bulkRequest);

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
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
        auditLogsRule.assertAtLeast(1, auditPredicate(INDEX_EVENT).withEffectiveUser(LIMITED_WRITE_USER));
        auditLogsRule.assertAtLeast(1, missingPrivilege(LIMITED_WRITE_USER, "RestoreSnapshotRequest"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    public void shouldRestoreSnapshot_failureOperationForbidden() throws IOException {
        String snapshotName = "restore-snapshot-negative-forbidden-operation";
        long snapshotGetCount;
        Settings indexSettings = Settings.builder().put("index.number_of_shards", 1).put("index.number_of_replicas", 0).build();
        IndexOperationsHelper.createIndex(cluster, WRITE_SONG_INDEX_NAME, indexSettings);
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_WRITE_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
            // 1. create some documents
            BulkRequest bulkRequest = BulkRequest.of(
                r -> r.operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Eins").document(SONGS[0].asMap())))
                    .operations(op -> op.index(i -> i.index(WRITE_SONG_INDEX_NAME).id("Zwei").document(SONGS[1].asMap())))
                    .refresh(Refresh.True)
            );
            client.bulk(bulkRequest);

            // 2. create snapshot repository
            steps.createSnapshotRepository(TEST_SNAPSHOT_REPOSITORY_NAME, cluster.getSnapshotDirPath(), "fs");

            // 3. create snapshot
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName, WRITE_SONG_INDEX_NAME);

            // 4. wait till snapshot is ready
            snapshotGetCount = steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, snapshotName);
        }
        // 5. restore the snapshot
        try (CloseableOpenSearchClient client = cluster.getClient(LIMITED_READ_USER)) {
            SnapshotSteps steps = new SnapshotSteps(client);
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
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "PutRepositoryRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "CreateSnapshotRequest"));
        auditLogsRule.assertAtLeast(1, grantedPrivilege(LIMITED_WRITE_USER, "BulkRequest"));
        auditLogsRule.assertAtLeast(1, missingPrivilege(LIMITED_READ_USER, "RestoreSnapshotRequest"));
        auditLogsRule.assertAtLeast(snapshotGetCount, grantedPrivilege(LIMITED_WRITE_USER, "GetSnapshotsRequest"));
        auditLogsRule.assertAtLeast(2, grantedPrivilege(LIMITED_WRITE_USER, "PutMappingRequest"));
    }

    @Test
    // required permissions: "indices:admin/create"
    public void createIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("create_index_positive");
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            CreateIndexRequest createIndexRequest = CreateIndexRequest.of(r -> r.index(indexName));
            CreateIndexResponse createIndexResponse = client.indices().create(createIndexRequest);

            assertThat(createIndexResponse, isSuccessfulCreateIndexResponse(indexName));
            assertThat(cluster, indexExists(indexName));
        }
    }

    @Test
    public void createIndex_negative() throws IOException {
        String indexName = "create_index_negative";
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            CreateIndexRequest createIndexRequest = CreateIndexRequest.of(r -> r.index(indexName));

            assertThatThrownBy(() -> client.indices().create(createIndexRequest), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(indexName)));
        }
    }

    @Test
    // required permissions: "indices:admin/get"
    public void checkIfIndexExists_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("index_exists_positive");
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            BooleanResponse exists = client.indices().exists(ExistsRequest.of(r -> r.index(indexName)));

            assertThat(exists.value(), is(false));
        }
    }

    @Test
    public void checkIfIndexExists_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "index_exists_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().exists(ExistsRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().exists(ExistsRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> client.indices().exists(ExistsRequest.of(r -> r.index("*"))), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/delete"
    public void deleteIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("delete_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            DeleteIndexRequest deleteIndexRequest = DeleteIndexRequest.of(r -> r.index(indexName));
            var response = client.indices().delete(deleteIndexRequest);

            assertThat(response.acknowledged(), is(true));
            assertThat(cluster, not(indexExists(indexName)));
        }
    }

    @Test
    public void deleteIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "delete_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().delete(DeleteIndexRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().delete(DeleteIndexRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> client.indices().delete(DeleteIndexRequest.of(r -> r.index("*"))), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: indices:admin/aliases, indices:admin/delete
    public void shouldDeleteIndexByAliasRequest_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("delete_index_by_alias_request_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            UpdateAliasesRequest request = UpdateAliasesRequest.of(
                r -> r.actions(a -> a.removeIndex(RemoveIndexAction.of(add -> add.index(indexName))))
            );

            var response = client.indices().updateAliases(request);

            assertThat(response.acknowledged(), is(true));
            assertThat(cluster, not(indexExists(indexName)));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES).withRestRequest(POST, "/_aliases")
        );
        auditLogsRule.assertAtLeast(
            1,
            grantedPrivilege(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES, "IndicesAliasesRequest")
        );
        auditLogsRule.assertAtLeast(
            1,
            auditPredicate(INDEX_EVENT).withEffectiveUser(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)
        );
    }

    @Test
    public void shouldDeleteIndexByAliasRequest_negative() throws IOException {
        String indexName = "delete_index_by_alias_request_negative";
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            UpdateAliasesRequest request = UpdateAliasesRequest.of(
                r -> r.actions(a -> a.removeIndex(RemoveIndexAction.of(add -> add.index(indexName))))
            );
            assertThatThrownBy(() -> client.indices().updateAliases(request), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/get"
    public void getIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("get_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            GetIndexRequest getIndexRequest = GetIndexRequest.of(r -> r.index(indexName));
            GetIndexResponse response = client.indices().get(getIndexRequest);

            assertThat(response, getIndexResponseContainsIndices(indexName));
        }
    }

    @Test
    public void getIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "get_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().get(GetIndexRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().get(GetIndexRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> client.indices().get(GetIndexRequest.of(r -> r.index("*"))), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/close", "indices:admin/close*"
    public void closeIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("close_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            CloseIndexRequest closeIndexRequest = CloseIndexRequest.of(r -> r.index(indexName));
            CloseIndexResponse response = client.indices().close(closeIndexRequest);

            assertThat(response, isSuccessfulCloseIndexResponse());
            assertThat(cluster, indexStateIsEqualTo(indexName, IndexMetadata.State.CLOSE));
        }
    }

    @Test
    public void closeIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "close_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().close(CloseIndexRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().close(CloseIndexRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> client.indices().close(CloseIndexRequest.of(r -> r.index("*"))), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/open"
    public void openIndex_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("open_index_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);
        IndexOperationsHelper.closeIndex(cluster, indexName);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            OpenRequest closeIndexRequest = OpenRequest.of(r -> r.index(indexName));
            OpenResponse response = client.indices().open(closeIndexRequest);

            assertThat(response, isSuccessfulOpenIndexResponse());
            assertThat(cluster, indexStateIsEqualTo(indexName, IndexMetadata.State.OPEN));
        }
    }

    @Test
    public void openIndex_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "open_index_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().open(OpenRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().open(OpenRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> client.indices().open(OpenRequest.of(r -> r.index("*"))), statusException(FORBIDDEN));
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

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            HealthResponse healthResponse = client.cluster()
                .health(
                    HealthRequest.of(
                        r -> r.index(sourceIndexName)
                            .waitForNoRelocatingShards(true)
                            .waitForActiveShards(s -> s.count(4))
                            .waitForNoInitializingShards(true)
                            .waitForStatus(HealthStatus.Green)
                    )
                );

            assertThat(healthResponse.status(), is(HealthStatus.Green));

            ShrinkRequest resizeRequest = ShrinkRequest.of(r -> r.target(targetIndexName).index(sourceIndexName));
            ShrinkResponse response = client.indices().shrink(resizeRequest);

            assertThat(response, isSuccessfulResizeResponse(targetIndexName));
            assertThat(cluster, indexExists(targetIndexName));
        }
    }

    @Test
    public void shrinkIndex_negative() throws IOException {

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            // user cannot access target index
            String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("shrink_index_negative_source");
            String targetIndexName = "shrink_index_negative_target";

            ShrinkRequest resizeRequest = ShrinkRequest.of(r -> r.target(targetIndexName).index(sourceIndexName));

            assertThatThrownBy(() -> client.indices().shrink(resizeRequest), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            // user cannot access source index
            String sourceIndexName = "shrink_index_negative_source";
            String targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("shrink_index_negative_target");

            ShrinkRequest resizeRequest = ShrinkRequest.of(r -> r.target(targetIndexName).index(sourceIndexName));

            assertThatThrownBy(() -> client.indices().shrink(resizeRequest), statusException(FORBIDDEN));
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

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            CloneIndexRequest cloneRequest = CloneIndexRequest.of(r -> r.target(targetIndexName).index(sourceIndexName));
            CloneIndexResponse response = client.indices().clone(cloneRequest);

            assertThat(response, isSuccessfulCloneResponse(targetIndexName));
            assertThat(cluster, indexExists(targetIndexName));

            // can't clone the same index twice, target already exists
            CloneIndexRequest repeatCloneRequest = CloneIndexRequest.of(r -> r.target(targetIndexName).index(sourceIndexName));
            assertThatThrownBy(() -> client.indices().clone(repeatCloneRequest), statusException(BAD_REQUEST));
        }
    }

    @Test
    public void cloneIndex_negative() throws IOException {
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            // user cannot access target index
            String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clone_index_negative_source");
            String targetIndexName = "clone_index_negative_target";

            CloneIndexRequest cloneRequest = CloneIndexRequest.of(r -> r.target(targetIndexName).index(sourceIndexName));

            assertThatThrownBy(() -> client.indices().clone(cloneRequest), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            // user cannot access source index
            String sourceIndexName = "clone_index_negative_source";
            String targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clone_index_negative_target");

            CloneIndexRequest cloneRequest = CloneIndexRequest.of(r -> r.target(targetIndexName).index(sourceIndexName));

            assertThatThrownBy(() -> client.indices().clone(cloneRequest), statusException(FORBIDDEN));
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

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            SplitRequest resizeRequest = SplitRequest.of(
                r -> r.target(targetIndexName).index(sourceIndexName).settings("index.number_of_shards", JsonData.of(2))
            );
            SplitResponse response = client.indices().split(resizeRequest);

            assertThat(response, isSuccessfulSplitResponse(targetIndexName));
            assertThat(cluster, indexExists(targetIndexName));
        }
    }

    @Test
    public void splitIndex_negative() throws IOException {

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            // user cannot access target index
            String sourceIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("split_index_negative_source");
            String targetIndexName = "split_index_negative_target";

            SplitRequest resizeRequest = SplitRequest.of(
                r -> r.target(targetIndexName).index(sourceIndexName).settings("index.number_of_shards", JsonData.of(2))
            );

            assertThatThrownBy(() -> client.indices().split(resizeRequest), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            // user cannot access source index
            String sourceIndexName = "split_index_negative_source";
            String targetIndexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("split_index_negative_target");

            SplitRequest resizeRequest = SplitRequest.of(
                r -> r.target(targetIndexName).index(sourceIndexName).settings("index.number_of_shards", JsonData.of(2))
            );

            assertThatThrownBy(() -> client.indices().split(resizeRequest), statusException(FORBIDDEN));
            assertThat(cluster, not(indexExists(targetIndexName)));
        }
    }

    @Test
    // required permissions: "indices:monitor/settings/get"
    public void getIndexSettings_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("get_index_settings_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            GetIndicesSettingsRequest getSettingsRequest = GetIndicesSettingsRequest.of(r -> r.index(indexName));
            GetIndicesSettingsResponse response = client.indices().getSettings(getSettingsRequest);

            assertThat(response, getSettingsResponseContainsIndices(indexName));
        }
    }

    @Test
    public void getIndexSettings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "get_index_settings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().getSettings(GetIndicesSettingsRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices()
                    .getSettings(GetIndicesSettingsRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().getSettings(GetIndicesSettingsRequest.of(r -> r.index("*"))),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: "indices:admin/settings/update"
    public void updateIndexSettings_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("update_index_settings_positive");
        Settings initialSettings = Settings.builder().put("index.number_of_replicas", "2").build();
        IndexSettings updatedSettings = IndexSettings.of(s -> s.numberOfReplicas(4));
        IndexOperationsHelper.createIndex(cluster, indexName, initialSettings);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            PutIndicesSettingsRequest updateSettingsRequest = PutIndicesSettingsRequest.of(
                r -> r.index(indexName).settings(updatedSettings)
            );
            var response = client.indices().putSettings(updateSettingsRequest);

            assertThat(response.acknowledged(), is(true));
            assertThat(cluster, indexSettingsContainValues(indexName, Settings.builder().put("index.number_of_replicas", "4").build()));
        }
    }

    @Test
    public void updateIndexSettings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "update_index_settings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        IndexSettings settingsToUpdate = IndexSettings.of(s -> s.numberOfReplicas(2));
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices()
                    .putSettings(PutIndicesSettingsRequest.of(r -> r.index(indexThatUserHasNoAccessTo).settings(settingsToUpdate))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices()
                    .putSettings(
                        PutIndicesSettingsRequest.of(
                            r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo).settings(settingsToUpdate)
                        )
                    ),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().putSettings(PutIndicesSettingsRequest.of(r -> r.index("*").settings(settingsToUpdate))),
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

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            PutMappingRequest putMappingRequest = PutMappingRequest.of(
                r -> r.index(indexName).properties("message", Property.of(p -> p.text(t -> t)))
            );
            var response = client.indices().putMapping(putMappingRequest);

            assertThat(response.acknowledged(), is(true));
            assertThat(cluster, indexMappingIsEqualTo(indexName, indexMapping));
        }
    }

    @Test
    public void createIndexMappings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "create_index_mappings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            assertThatThrownBy(
                () -> client.indices()
                    .putMapping(
                        PutMappingRequest.of(
                            r -> r.index(indexThatUserHasNoAccessTo).properties("message", Property.of(p -> p.text(t -> t)))
                        )
                    ),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices()
                    .putMapping(
                        PutMappingRequest.of(
                            r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo)
                                .properties("message", Property.of(p -> p.text(t -> t)))
                        )
                    ),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices()
                    .putMapping(PutMappingRequest.of(r -> r.index("*").properties("message", Property.of(p -> p.text(t -> t))))),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    // required permissions: "indices:admin/mappings/get"
    public void getIndexMappings_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("get_index_mappings_positive");
        Map<String, Object> indexMapping = Map.of("properties", Map.of("message", Map.of("type", "text")));
        IndexOperationsHelper.createIndex(cluster, indexName);
        IndexOperationsHelper.createMapping(cluster, indexName, indexMapping);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            GetMappingRequest getMappingsRequest = GetMappingRequest.of(r -> r.index(indexName));
            GetMappingResponse response = client.indices().getMapping(getMappingsRequest);

            assertThat(response, getMappingsResponseContainsIndices(indexName));
        }
    }

    @Test
    public void getIndexMappings_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "get_index_mappings_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().getMapping(GetMappingRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().getMapping(GetMappingRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> client.indices().getMapping(GetMappingRequest.of(r -> r.index("*"))), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/cache/clear"
    public void clearIndexCache_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("clear_index_cache_positive");
        IndexOperationsHelper.createIndex(cluster, indexName);

        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            ClearCacheRequest clearIndicesCacheRequest = ClearCacheRequest.of(r -> r.index(indexName));
            ClearCacheResponse response = client.indices().clearCache(clearIndicesCacheRequest);

            assertThat(response, isSuccessfulClearIndicesCacheResponse());
        }
    }

    @Test
    public void clearIndexCache_negative() throws IOException {
        String indexThatUserHasNoAccessTo = "clear_index_cache_negative";
        String indexThatUserHasAccessTo = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat(indexThatUserHasNoAccessTo);
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {

            assertThatThrownBy(
                () -> client.indices().clearCache(ClearCacheRequest.of(r -> r.index(indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(
                () -> client.indices().clearCache(ClearCacheRequest.of(r -> r.index(indexThatUserHasAccessTo, indexThatUserHasNoAccessTo))),
                statusException(FORBIDDEN)
            );
            assertThatThrownBy(() -> client.indices().clearCache(ClearCacheRequest.of(r -> r.index("*"))), statusException(FORBIDDEN));
        }
    }

    @Test
    // required permissions: "indices:admin/create", "indices:admin/aliases"
    public void shouldCreateIndexWithAlias_positive() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("create_index_with_alias_positive");
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)) {
            CreateIndexRequest createIndexRequest = CreateIndexRequest.of(
                r -> r.index(indexName).aliases(ALIAS_CREATE_INDEX_WITH_ALIAS_POSITIVE, Alias.builder().build())
            );

            CreateIndexResponse createIndexResponse = client.indices().create(createIndexRequest);

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
        auditLogsRule.assertAtLeast(
            1,
            grantedPrivilege(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES, "CreateIndexRequest")
        );
        auditLogsRule.assertAtLeast(
            1,
            auditPredicate(INDEX_EVENT).withEffectiveUser(USER_ALLOWED_TO_PERFORM_INDEX_OPERATIONS_ON_SELECTED_INDICES)
        );
    }

    @Test
    public void shouldCreateIndexWithAlias_negative() throws IOException {
        String indexName = INDICES_ON_WHICH_USER_CAN_PERFORM_INDEX_OPERATIONS_PREFIX.concat("create_index_with_alias_negative");
        try (CloseableOpenSearchClient client = cluster.getClient(USER_ALLOWED_TO_CREATE_INDEX)) {
            CreateIndexRequest createIndexRequest = CreateIndexRequest.of(
                r -> r.index(indexName).aliases(ALIAS_CREATE_INDEX_WITH_ALIAS_NEGATIVE, Alias.builder().build())
            );

            assertThatThrownBy(() -> client.indices().create(createIndexRequest), statusException(FORBIDDEN));

            assertThat(internalClient, not(aliasExists(ALIAS_CREATE_INDEX_WITH_ALIAS_NEGATIVE)));
        }
        auditLogsRule.assertExactlyOne(
            userAuthenticated(USER_ALLOWED_TO_CREATE_INDEX).withRestRequest(PUT, "/index_operations_create_index_with_alias_negative")
        );
        auditLogsRule.assertExactlyOne(missingPrivilege(USER_ALLOWED_TO_CREATE_INDEX, "CreateIndexRequest"));
    }
}
