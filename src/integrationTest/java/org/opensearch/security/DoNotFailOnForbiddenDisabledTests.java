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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DoNotFailOnForbiddenDisabledTests extends AbstractDoNotFailOnForbiddenTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_USER, STATS_USER)
        .anonymousAuth(false)
        .build();

    public DoNotFailOnForbiddenDisabledTests() {
        super(cluster);
    }

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(MARVELOUS_SONGS).id(ID_1).source(SONGS[0].asMap()))
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(MARVELOUS_SONGS).id(ID_2).source(SONGS[1].asMap()))
                .actionGet();
            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(MARVELOUS_SONGS).id(ID_3).source(SONGS[2].asMap()))
                .actionGet();

            client.index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index(HORRIBLE_SONGS).id(ID_4).source(SONGS[3].asMap()))
                .actionGet();

            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(MARVELOUS_SONGS, HORRIBLE_SONGS).alias(BOTH_INDEX_ALIAS)
                    )
                )
                .actionGet();
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        new IndicesAliasesRequest.AliasActions(ADD).indices(HORRIBLE_SONGS).alias(FORBIDDEN_INDEX_ALIAS)
                    )
                )
                .actionGet();

        }
    }

    @Test
    public void shouldPerformCatIndices_positive() throws IOException {
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_USER)) {
            Request getIndicesRequest = new Request("GET", "/_cat/indices");
            // High level client doesn't support _cat/_indices API
            Response getIndicesResponse = restHighLevelClient.getLowLevelClient().performRequest(getIndicesRequest);
            List<String> indexes = new BufferedReader(
                new InputStreamReader(getIndicesResponse.getEntity().getContent(), StandardCharsets.UTF_8)
            ).lines().collect(Collectors.toList());

            assertThat(indexes.size(), equalTo(1));
            assertThat(indexes.get(0), containsString("marvelous_songs"));
        }
    }
}
