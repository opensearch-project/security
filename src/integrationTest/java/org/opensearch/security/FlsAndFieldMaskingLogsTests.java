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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.plugin.mapper.MapperSizePlugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.log.LogsRule;

import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.security.FlsAndFieldMaskingTests.assertSearchHitsDoNotContainField;
import static org.opensearch.security.Song.FIELD_STARS;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class FlsAndFieldMaskingLogsTests {

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of("plugins.security.restapi.roles_enabled", List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()))
        )
        .plugin(MapperSizePlugin.class)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .build();

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

    static TestSecurityConfig.User createUserWithRole(String userName, TestSecurityConfig.Role role) {
        TestSecurityConfig.User user = new TestSecurityConfig.User(userName);
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.createRole(role.getName(), role).assertStatusCode(201);
            client.createUser(user.getName(), user).assertStatusCode(201);
            client.assignRoleToUser(user.getName(), role.getName()).assertStatusCode(200);
        }
        return user;
    }

    @Rule
    public LogsRule valveLogsRule = new LogsRule("org.opensearch.security.configuration.DlsFlsValveImpl");

    @Test
    public void testFilteredFlsDlsConfig() throws IOException {
        String indexName = "fls_index";
        String otherIndexName = "other_fls_index";
        TestSecurityConfig.Role userRole = new TestSecurityConfig.Role("fls_exclude_stars_reader").clusterPermissions(
            "cluster_composite_ops_ro"
        ).indexPermissions("read").fls("~".concat(FIELD_STARS)).on("*");
        TestSecurityConfig.User user = createUserWithRole("fls_user", userRole);
        List<String> docIds = createIndexWithDocs(indexName, SONGS[0], SONGS[1]);
        createIndexWithDocs(otherIndexName, SONGS[0], SONGS[1]);

        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(user)) {
            // search
            SearchResponse searchResponse = restHighLevelClient.search(new SearchRequest(indexName), DEFAULT);

            valveLogsRule.assertThatContainExactly(
                "Filtered DLS/FLS Config: EvaluatedDlsFlsConfig [dlsQueriesByIndex={}, flsByIndex={fls_index=[~stars]}, fieldMaskingByIndex={}]"
            );

            assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);

            // search with index pattern
            // searchResponse = restHighLevelClient.search(new SearchRequest("*".concat(indexName)), DEFAULT);
            //
            // assertSearchHitsDoNotContainField(searchResponse, FIELD_STARS);
        }
    }

}
