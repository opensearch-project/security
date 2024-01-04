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

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.action.search.DeletePitResponse;
import org.opensearch.action.search.GetAllPitNodesResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.search.builder.PointInTimeBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.PitResponseMatchers.deleteResponseContainsExactlyPitWithIds;
import static org.opensearch.test.framework.matcher.PitResponseMatchers.getAllResponseContainsExactlyPitWithIds;
import static org.opensearch.test.framework.matcher.PitResponseMatchers.isSuccessfulCreatePitResponse;
import static org.opensearch.test.framework.matcher.PitResponseMatchers.isSuccessfulDeletePitResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentsInAnyOrder;

@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class PointInTimeOperationTest {

    private static final String FIRST_SONG_INDEX = "song-index-1";
    private static final String FIRST_INDEX_ALIAS = "song-index-1-alias";
    private static final String SECOND_SONG_INDEX = "song-index-2";
    private static final String SECOND_INDEX_ALIAS = "song-index-2-alias";

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    /**
    * User who is allowed to perform PIT operations only on the {@link #FIRST_SONG_INDEX}
    */
    private static final TestSecurityConfig.User LIMITED_POINT_IN_TIME_USER = new TestSecurityConfig.User("limited_point_in_time_user")
        .roles(
            new TestSecurityConfig.Role("limited_point_in_time_user").indexPermissions(
                "indices:data/read/point_in_time/create",
                "indices:data/read/point_in_time/delete",
                "indices:data/read/search",
                "indices:data/read/point_in_time/readall", // anyway user needs the all indexes permission (*) to find all pits
                "indices:monitor/point_in_time/segments" // anyway user needs the all indexes permission (*) to list all pits segments
            ).on(FIRST_SONG_INDEX)
        );
    /**
    * User who is allowed to perform PIT operations on all indices
    */
    private static final TestSecurityConfig.User POINT_IN_TIME_USER = new TestSecurityConfig.User("point_in_time_user").roles(
        new TestSecurityConfig.Role("point_in_time_user").indexPermissions(
            "indices:data/read/point_in_time/create",
            "indices:data/read/point_in_time/delete",
            "indices:data/read/search",
            "indices:data/read/point_in_time/readall",
            "indices:monitor/point_in_time/segments"
        ).on("*")
    );

    private static final String ID_1 = "1";
    private static final String ID_2 = "2";
    private static final String ID_3 = "3";
    private static final String ID_4 = "4";

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(FIRST_SONG_INDEX).id(ID_1).source(SONGS[0].asMap()))
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(FIRST_SONG_INDEX).id(ID_2).source(SONGS[1].asMap()))
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(FIRST_SONG_INDEX).id(ID_3).source(SONGS[2].asMap()))
                .actionGet();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(FIRST_SONG_INDEX).alias(FIRST_INDEX_ALIAS)
                    )
                )
                .actionGet();

            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(SECOND_SONG_INDEX).id(ID_4).source(SONGS[3].asMap()))
                .actionGet();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(SECOND_SONG_INDEX).alias(SECOND_INDEX_ALIAS)
                    )
                )
                .actionGet();
        }
    }

    @Before
    public void cleanUpPits() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            restHighLevelClient.deleteAllPits(DEFAULT);
        }
    }

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_POINT_IN_TIME_USER, POINT_IN_TIME_USER)
        .build();

    @Test
    public void createPit_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            CreatePitRequest createPitRequest = new CreatePitRequest(TimeValue.timeValueMinutes(30), false, FIRST_SONG_INDEX);

            CreatePitResponse createPitResponse = restHighLevelClient.createPit(createPitRequest, DEFAULT);

            assertThat(createPitResponse, isSuccessfulCreatePitResponse());
        }
    }

    @Test
    public void createPitWithIndexAlias_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            CreatePitRequest createPitRequest = new CreatePitRequest(TimeValue.timeValueMinutes(30), false, FIRST_INDEX_ALIAS);

            CreatePitResponse createPitResponse = restHighLevelClient.createPit(createPitRequest, DEFAULT);

            assertThat(createPitResponse, isSuccessfulCreatePitResponse());
        }
    }

    @Test
    public void createPit_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            CreatePitRequest createPitRequest = new CreatePitRequest(TimeValue.timeValueMinutes(30), false, SECOND_SONG_INDEX);

            assertThatThrownBy(() -> restHighLevelClient.createPit(createPitRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void createPitWithIndexAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            CreatePitRequest createPitRequest = new CreatePitRequest(TimeValue.timeValueMinutes(30), false, SECOND_INDEX_ALIAS);

            assertThatThrownBy(() -> restHighLevelClient.createPit(createPitRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void listAllPits_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(POINT_IN_TIME_USER)) {
            String firstIndexPit = createPitForIndices(FIRST_SONG_INDEX);
            String secondIndexPit = createPitForIndices(SECOND_SONG_INDEX);

            GetAllPitNodesResponse getAllPitsResponse = restHighLevelClient.getAllPits(DEFAULT);

            assertThat(getAllPitsResponse, getAllResponseContainsExactlyPitWithIds(firstIndexPit, secondIndexPit));
        }
    }

    @Test
    public void listAllPits_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            assertThatThrownBy(() -> restHighLevelClient.getAllPits(DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void deletePit_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(FIRST_SONG_INDEX);

            DeletePitResponse deletePitResponse = restHighLevelClient.deletePit(new DeletePitRequest(existingPitId), DEFAULT);
            assertThat(deletePitResponse, isSuccessfulDeletePitResponse());
            assertThat(deletePitResponse, deleteResponseContainsExactlyPitWithIds(existingPitId));
        }
    }

    @Test
    public void deletePitCreatedWithIndexAlias_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(FIRST_INDEX_ALIAS);

            DeletePitResponse deletePitResponse = restHighLevelClient.deletePit(new DeletePitRequest(existingPitId), DEFAULT);
            assertThat(deletePitResponse, isSuccessfulDeletePitResponse());
            assertThat(deletePitResponse, deleteResponseContainsExactlyPitWithIds(existingPitId));
        }
    }

    @Test
    public void deletePit_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(SECOND_SONG_INDEX);

            assertThatThrownBy(
                () -> restHighLevelClient.deletePit(new DeletePitRequest(existingPitId), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    public void deletePitCreatedWithIndexAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(SECOND_INDEX_ALIAS);

            assertThatThrownBy(
                () -> restHighLevelClient.deletePit(new DeletePitRequest(existingPitId), DEFAULT),
                statusException(FORBIDDEN)
            );
        }
    }

    @Test
    public void deleteAllPits_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(POINT_IN_TIME_USER)) {
            String firstIndexPit = createPitForIndices(FIRST_SONG_INDEX);
            String secondIndexPit = createPitForIndices(SECOND_SONG_INDEX);

            DeletePitResponse deletePitResponse = restHighLevelClient.deleteAllPits(DEFAULT);
            assertThat(deletePitResponse, isSuccessfulDeletePitResponse());
            assertThat(deletePitResponse, deleteResponseContainsExactlyPitWithIds(firstIndexPit, secondIndexPit));
        }
    }

    @Test
    public void deleteAllPits_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            assertThatThrownBy(() -> restHighLevelClient.deleteAllPits(DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void searchWithPit_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(FIRST_SONG_INDEX);

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.source(new SearchSourceBuilder().pointInTimeBuilder(new PointInTimeBuilder(existingPitId)));

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);
            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(
                searchResponse,
                searchHitsContainDocumentsInAnyOrder(
                    Pair.of(FIRST_SONG_INDEX, ID_1),
                    Pair.of(FIRST_SONG_INDEX, ID_2),
                    Pair.of(FIRST_SONG_INDEX, ID_3)
                )
            );
        }
    }

    @Test
    public void searchWithPitCreatedWithIndexAlias_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(FIRST_INDEX_ALIAS);

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.source(new SearchSourceBuilder().pointInTimeBuilder(new PointInTimeBuilder(existingPitId)));

            SearchResponse searchResponse = restHighLevelClient.search(searchRequest, DEFAULT);
            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(
                searchResponse,
                searchHitsContainDocumentsInAnyOrder(
                    Pair.of(FIRST_SONG_INDEX, ID_1),
                    Pair.of(FIRST_SONG_INDEX, ID_2),
                    Pair.of(FIRST_SONG_INDEX, ID_3)
                )
            );
        }
    }

    @Test
    public void searchWithPit_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(SECOND_SONG_INDEX);

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.source(new SearchSourceBuilder().pointInTimeBuilder(new PointInTimeBuilder(existingPitId)));

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void searchWithPitCreatedWithIndexAlias_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(SECOND_INDEX_ALIAS);

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.source(new SearchSourceBuilder().pointInTimeBuilder(new PointInTimeBuilder(existingPitId)));

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void listPitSegments_positive() throws IOException {
        try (TestRestClient restClient = cluster.getRestClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(FIRST_SONG_INDEX);
            String body = String.format("{\"pit_id\":[\"%s\"]}", existingPitId);
            HttpResponse response = restClient.getWithJsonBody("/_cat/pit_segments", body);

            response.assertStatusCode(OK.getStatus());
        }
    }

    @Test
    public void listPitSegmentsCreatedWithIndexAlias_positive() throws IOException {
        try (TestRestClient restClient = cluster.getRestClient(POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(FIRST_INDEX_ALIAS);
            String body = String.format("{\"pit_id\":[\"%s\"]}", existingPitId);
            HttpResponse response = restClient.getWithJsonBody("/_cat/pit_segments", body);

            response.assertStatusCode(OK.getStatus());
        }
    }

    @Test
    public void listPitSegments_negative() throws IOException {
        try (TestRestClient restClient = cluster.getRestClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(SECOND_SONG_INDEX);
            String body = String.format("{\"pit_id\":[\"%s\"]}", existingPitId);
            HttpResponse response = restClient.getWithJsonBody("/_cat/pit_segments", body);

            response.assertStatusCode(FORBIDDEN.getStatus());
        }
    }

    @Test
    public void listPitSegmentsCreatedWithIndexAlias_negative() throws IOException {
        try (TestRestClient restClient = cluster.getRestClient(LIMITED_POINT_IN_TIME_USER)) {
            String existingPitId = createPitForIndices(SECOND_INDEX_ALIAS);
            String body = String.format("{\"pit_id\":[\"%s\"]}", existingPitId);
            HttpResponse response = restClient.getWithJsonBody("/_cat/pit_segments", body);

            response.assertStatusCode(FORBIDDEN.getStatus());
        }
    }

    @Test
    public void listAllPitSegments_positive() {
        try (TestRestClient restClient = cluster.getRestClient(POINT_IN_TIME_USER)) {
            HttpResponse response = restClient.get("_cat/pit_segments/_all");

            response.assertStatusCode(OK.getStatus());
        }
    }

    @Test
    public void listAllPitSegments_negative() {
        try (TestRestClient restClient = cluster.getRestClient(LIMITED_POINT_IN_TIME_USER)) {
            HttpResponse response = restClient.get("_cat/pit_segments/_all");

            response.assertStatusCode(FORBIDDEN.getStatus());
        }
    }

    /**
    * Creates PIT for given indices. Returns PIT id.
    */
    private String createPitForIndices(String... indices) throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            CreatePitRequest createPitRequest = new CreatePitRequest(TimeValue.timeValueMinutes(30), false, indices);

            CreatePitResponse createPitResponse = restHighLevelClient.createPit(createPitRequest, DEFAULT);

            assertThat(createPitResponse, isSuccessfulCreatePitResponse());
            return createPitResponse.getId();
        }
    }

}
