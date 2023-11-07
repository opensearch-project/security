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

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.SearchRequestFactory;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.security.Song.ARTIST_FIRST;
import static org.opensearch.security.Song.FIELD_ARTIST;
import static org.opensearch.security.Song.FIELD_GENRE;
import static org.opensearch.security.Song.FIELD_LYRICS;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.opensearch.security.Song.FIELD_TITLE;
import static org.opensearch.security.Song.GENRE_JAZZ;
import static org.opensearch.security.Song.GENRE_ROCK;
import static org.opensearch.security.Song.QUERY_TITLE_MAGNUM_OPUS;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.Song.TITLE_MAGNUM_OPUS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitContainsFieldWithValue;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitDoesNotContainField;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentWithId;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentsInAnyOrder;

/**
* This is a parameterized test so that one test class is used to test security plugin behaviour when <code>ccsMinimizeRoundtrips</code>
* option is enabled or disabled. Method {@link #parameters()} is a source of parameters values.
*/

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class CrossClusterSearchTests {

    private static final String SONG_INDEX_NAME = "song_lyrics";

    private static final String PROHIBITED_SONG_INDEX_NAME = "prohibited_song_lyrics";

    public static final String REMOTE_CLUSTER_NAME = "ccsRemote";
    public static final String REMOTE_SONG_INDEX = REMOTE_CLUSTER_NAME + ":" + SONG_INDEX_NAME;

    public static final String SONG_ID_1R = "remote-00001";
    public static final String SONG_ID_2L = "local-00002";
    public static final String SONG_ID_3R = "remote-00003";
    public static final String SONG_ID_4L = "local-00004";
    public static final String SONG_ID_5R = "remote-00005";
    public static final String SONG_ID_6R = "remote-00006";

    private static final Role LIMITED_ROLE = new Role("limited_role").indexPermissions(
        "indices:data/read/search",
        "indices:admin/shards/search_shards"
    ).on(SONG_INDEX_NAME, "user-${user.name}-${attr.internal.type}");

    private static final Role DLS_ROLE_ROCK = new Role("dls_role_rock").indexPermissions(
        "indices:data/read/search",
        "indices:data/read/get",
        "indices:admin/shards/search_shards"
    ).dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_GENRE, GENRE_ROCK)).on(SONG_INDEX_NAME);

    private static final Role DLS_ROLE_JAZZ = new Role("dls_role_jazz").indexPermissions(
        "indices:data/read/search",
        "indices:data/read/get",
        "indices:admin/shards/search_shards"
    ).dls(String.format("{\"match\":{\"%s\":\"%s\"}}", FIELD_GENRE, GENRE_JAZZ)).on(SONG_INDEX_NAME);

    private static final Role FLS_EXCLUDE_LYRICS_ROLE = new Role("fls_exclude_lyrics_role").indexPermissions(
        "indices:data/read/search",
        "indices:data/read/get",
        "indices:admin/shards/search_shards"
    ).fls("~" + FIELD_LYRICS).on(SONG_INDEX_NAME);

    private static final Role FLS_INCLUDE_TITLE_ROLE = new Role("fls_include_title_role").indexPermissions(
        "indices:data/read/search",
        "indices:data/read/get",
        "indices:admin/shards/search_shards"
    ).fls(FIELD_TITLE).on(SONG_INDEX_NAME);

    public static final String TYPE_ATTRIBUTE = "type";

    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS).attr(TYPE_ATTRIBUTE, "administrative");
    private static final User LIMITED_USER = new User("limited_user").attr(TYPE_ATTRIBUTE, "personal");

    private static final User FLS_INCLUDE_TITLE_USER = new User("fls_include_title_user");

    private static final User FLS_EXCLUDE_LYRICS_USER = new User("fls_exclude_lyrics_user");

    private static final User DLS_USER_ROCK = new User("dls-user-rock");

    private static final User DLS_USER_JAZZ = new User("dls-user-jazz");

    public static final String LIMITED_USER_INDEX_NAME = "user-" + LIMITED_USER.getName() + "-" + LIMITED_USER.getAttribute(TYPE_ATTRIBUTE);
    public static final String ADMIN_USER_INDEX_NAME = "user-" + ADMIN_USER.getName() + "-" + ADMIN_USER.getAttribute(TYPE_ATTRIBUTE);

    private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

    private final boolean ccsMinimizeRoundtrips;

    public static final String PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED = "plugins.security.restapi.roles_enabled";
    @ClassRule
    public static final LocalCluster remoteCluster = new LocalCluster.Builder().certificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .clusterName(REMOTE_CLUSTER_NAME)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .roles(LIMITED_ROLE, DLS_ROLE_ROCK, DLS_ROLE_JAZZ, FLS_EXCLUDE_LYRICS_ROLE, FLS_INCLUDE_TITLE_ROLE)
        .users(ADMIN_USER)
        .build();

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().certificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLE_REMOTE_CLIENT)
        .anonymousAuth(false)
        .clusterName("ccsLocal")
        .nodeSettings(Map.of(PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName())))
        .remote(REMOTE_CLUSTER_NAME, remoteCluster)
        .roles(LIMITED_ROLE, DLS_ROLE_ROCK, DLS_ROLE_JAZZ, FLS_EXCLUDE_LYRICS_ROLE, FLS_INCLUDE_TITLE_ROLE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_USER, DLS_USER_ROCK, DLS_USER_JAZZ, FLS_INCLUDE_TITLE_USER, FLS_EXCLUDE_LYRICS_USER)
        .build();

    @ParametersFactory(shuffle = false)
    public static Iterable<Object[]> parameters() {
        return List.of(new Object[] { true }, new Object[] { false });
    }

    public CrossClusterSearchTests(Boolean ccsMinimizeRoundtrips) {
        this.ccsMinimizeRoundtrips = ccsMinimizeRoundtrips;
    }

    @BeforeClass
    public static void createTestData() {
        try (Client client = remoteCluster.getInternalNodeClient()) {
            client.prepareIndex(SONG_INDEX_NAME).setId(SONG_ID_1R).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
            client.prepareIndex(SONG_INDEX_NAME).setId(SONG_ID_6R).setRefreshPolicy(IMMEDIATE).setSource(SONGS[5].asMap()).get();
            client.prepareIndex(PROHIBITED_SONG_INDEX_NAME).setId(SONG_ID_3R).setRefreshPolicy(IMMEDIATE).setSource(SONGS[1].asMap()).get();
            client.prepareIndex(LIMITED_USER_INDEX_NAME).setId(SONG_ID_5R).setRefreshPolicy(IMMEDIATE).setSource(SONGS[4].asMap()).get();
        }
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(SONG_INDEX_NAME).setId(SONG_ID_2L).setRefreshPolicy(IMMEDIATE).setSource(SONGS[2].asMap()).get();
            client.prepareIndex(PROHIBITED_SONG_INDEX_NAME).setId(SONG_ID_4L).setRefreshPolicy(IMMEDIATE).setSource(SONGS[3].asMap()).get();
        }
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.assignRoleToUser(LIMITED_USER.getName(), LIMITED_ROLE.getName()).assertStatusCode(200);
            client.assignRoleToUser(DLS_USER_ROCK.getName(), DLS_ROLE_ROCK.getName()).assertStatusCode(200);
            client.assignRoleToUser(DLS_USER_JAZZ.getName(), DLS_ROLE_JAZZ.getName()).assertStatusCode(200);
            client.assignRoleToUser(FLS_INCLUDE_TITLE_USER.getName(), FLS_INCLUDE_TITLE_ROLE.getName()).assertStatusCode(200);
            client.assignRoleToUser(FLS_EXCLUDE_LYRICS_USER.getName(), FLS_EXCLUDE_LYRICS_ROLE.getName()).assertStatusCode(200);
        }
    }

    @Test
    public void shouldFindDocumentOnRemoteCluster_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_SONG_INDEX);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(2));
            assertThat(response, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, SONG_ID_1R));
            assertThat(response, searchHitsContainDocumentWithId(1, SONG_INDEX_NAME, SONG_ID_6R));
        }
    }

    private SearchRequest searchAll(String indexName) {
        SearchRequest searchRequest = SearchRequestFactory.searchAll(indexName);
        searchRequest.setCcsMinimizeRoundtrips(ccsMinimizeRoundtrips);
        return searchRequest;
    }

    @Test
    public void shouldFindDocumentOnRemoteCluster_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":" + PROHIBITED_SONG_INDEX_NAME);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentOnRemoteClustersWhenStarIsUsedAsClusterName_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll("*" + ":" + SONG_INDEX_NAME);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            // only remote documents are found
            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(2));
            assertThat(response, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, SONG_ID_1R));
            assertThat(response, searchHitsContainDocumentWithId(1, SONG_INDEX_NAME, SONG_ID_6R));
        }
    }

    @Test
    public void shouldSearchForDocumentOnRemoteClustersWhenStarIsUsedAsClusterName_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll("*" + ":" + PROHIBITED_SONG_INDEX_NAME);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentOnBothClustersWhenIndexOnBothClusterArePointedOut_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = SearchRequestFactory.searchAll(REMOTE_SONG_INDEX, SONG_INDEX_NAME);
            searchRequest.setCcsMinimizeRoundtrips(ccsMinimizeRoundtrips);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(3));
            assertThat(
                response,
                searchHitsContainDocumentsInAnyOrder(
                    Pair.of(SONG_INDEX_NAME, SONG_ID_1R),
                    Pair.of(SONG_INDEX_NAME, SONG_ID_2L),
                    Pair.of(SONG_INDEX_NAME, SONG_ID_6R)
                )
            );
        }
    }

    @Test
    public void shouldSearchForDocumentOnBothClustersWhenIndexOnBothClusterArePointedOut_negativeLackOfLocalAccess() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            var searchRequest = SearchRequestFactory.searchAll(REMOTE_SONG_INDEX, PROHIBITED_SONG_INDEX_NAME);
            searchRequest.setCcsMinimizeRoundtrips(ccsMinimizeRoundtrips);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchForDocumentOnBothClustersWhenIndexOnBothClusterArePointedOut_negativeLackOfRemoteAccess() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            String remoteIndex = REMOTE_CLUSTER_NAME + ":" + PROHIBITED_SONG_INDEX_NAME;
            SearchRequest searchRequest = SearchRequestFactory.searchAll(remoteIndex, SONG_INDEX_NAME);
            searchRequest.setCcsMinimizeRoundtrips(ccsMinimizeRoundtrips);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchViaAllAliasOnRemoteCluster_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":_all");

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(4));
            assertThat(
                response,
                searchHitsContainDocumentsInAnyOrder(
                    Pair.of(SONG_INDEX_NAME, SONG_ID_1R),
                    Pair.of(SONG_INDEX_NAME, SONG_ID_6R),
                    Pair.of(PROHIBITED_SONG_INDEX_NAME, SONG_ID_3R),
                    Pair.of(LIMITED_USER_INDEX_NAME, SONG_ID_5R)
                )
            );
        }
    }

    @Test
    public void shouldSearchViaAllAliasOnRemoteCluster_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":_all");

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchAllIndexOnRemoteClusterWhenStarIsUsedAsIndexName_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":*");

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(4));
            assertThat(
                response,
                searchHitsContainDocumentsInAnyOrder(
                    Pair.of(SONG_INDEX_NAME, SONG_ID_1R),
                    Pair.of(SONG_INDEX_NAME, SONG_ID_6R),
                    Pair.of(PROHIBITED_SONG_INDEX_NAME, SONG_ID_3R),
                    Pair.of(LIMITED_USER_INDEX_NAME, SONG_ID_5R)
                )
            );
        }
    }

    @Test
    public void shouldSearchAllIndexOnRemoteClusterWhenStarIsUsedAsIndexName_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":*");

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldResolveUserNameExpressionInRoleIndexPattern_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":" + LIMITED_USER_INDEX_NAME);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, numberOfTotalHitsIsEqualTo(1));
        }
    }

    @Test
    public void shouldResolveUserNameExpressionInRoleIndexPattern_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":" + ADMIN_USER_INDEX_NAME);

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldSearchInIndexWithPrefix_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":song*");

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(2));
            assertThat(
                response,
                searchHitsContainDocumentsInAnyOrder(Pair.of(SONG_INDEX_NAME, SONG_ID_1R), Pair.of(SONG_INDEX_NAME, SONG_ID_6R))
            );
        }
    }

    @Test
    public void shouldSearchInIndexWithPrefix_negative() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            SearchRequest searchRequest = searchAll(REMOTE_CLUSTER_NAME + ":prohibited*");

            assertThatThrownBy(() -> restHighLevelClient.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldEvaluateDocumentLevelSecurityRulesOnRemoteClusterOnSearchRequest_caseRock() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DLS_USER_ROCK)) {
            SearchRequest searchRequest = searchAll(REMOTE_SONG_INDEX);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            // searching for all documents, so is it important that result contain only one document with id SONG_ID_1
            // and document with SONG_ID_6 is excluded from result set by DLS
            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(1));
            assertThat(response, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, SONG_ID_1R));
        }
    }

    @Test
    public void shouldEvaluateDocumentLevelSecurityRulesOnRemoteClusterOnSearchRequest_caseJazz() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(DLS_USER_JAZZ)) {
            SearchRequest searchRequest = searchAll(REMOTE_SONG_INDEX);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            // searching for all documents, so is it important that result contain only one document with id SONG_ID_6
            // and document with SONG_ID_1 is excluded from result set by DLS
            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(1));
            assertThat(response, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, SONG_ID_6R));
        }
    }

    @Test
    public void shouldHaveAccessOnlyToSpecificField() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(FLS_INCLUDE_TITLE_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(REMOTE_SONG_INDEX, QUERY_TITLE_MAGNUM_OPUS);
            searchRequest.setCcsMinimizeRoundtrips(ccsMinimizeRoundtrips);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(1));
            // document should contain only title field
            assertThat(response, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(response, searchHitDoesNotContainField(0, FIELD_ARTIST));
            assertThat(response, searchHitDoesNotContainField(0, FIELD_LYRICS));
            assertThat(response, searchHitDoesNotContainField(0, FIELD_STARS));
            assertThat(response, searchHitDoesNotContainField(0, FIELD_GENRE));
        }
    }

    @Test
    public void shouldLackAccessToSpecificField() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(FLS_EXCLUDE_LYRICS_USER)) {
            SearchRequest searchRequest = queryStringQueryRequest(REMOTE_SONG_INDEX, QUERY_TITLE_MAGNUM_OPUS);
            searchRequest.setCcsMinimizeRoundtrips(ccsMinimizeRoundtrips);

            SearchResponse response = restHighLevelClient.search(searchRequest, DEFAULT);

            assertThat(response, isSuccessfulSearchResponse());
            assertThat(response, numberOfTotalHitsIsEqualTo(1));
            // document should not contain lyrics field
            assertThat(response, searchHitDoesNotContainField(0, FIELD_LYRICS));

            assertThat(response, searchHitContainsFieldWithValue(0, FIELD_TITLE, TITLE_MAGNUM_OPUS));
            assertThat(response, searchHitContainsFieldWithValue(0, FIELD_ARTIST, ARTIST_FIRST));
            assertThat(response, searchHitContainsFieldWithValue(0, FIELD_STARS, 1));
            assertThat(response, searchHitContainsFieldWithValue(0, FIELD_GENRE, GENRE_ROCK));
        }
    }
}
