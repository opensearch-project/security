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

import java.util.Map;

import org.opensearch.action.admin.indices.close.CloseIndexRequest;
import org.opensearch.action.admin.indices.close.CloseIndexResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.framework.matcher.ClusterMatchers.indexExists;
import static org.opensearch.test.framework.matcher.ClusterMatchers.indexStateIsEqualTo;

public class IndexOperationsHelper {

    public static void createIndex(LocalCluster cluster, String indexName) {
        createIndex(cluster, indexName, Settings.EMPTY);
    }

    public static void createIndex(LocalCluster cluster, String indexName, Settings settings) {
        try (Client client = cluster.getInternalNodeClient()) {
            CreateIndexResponse createIndexResponse = client.admin()
                .indices()
                .create(new CreateIndexRequest(indexName).settings(settings))
                .actionGet();

            assertThat(createIndexResponse.isAcknowledged(), is(true));
            assertThat(createIndexResponse.isShardsAcknowledged(), is(true));
            assertThat(cluster, indexExists(indexName));
        }
    }

    public static void closeIndex(LocalCluster cluster, String indexName) {
        try (Client client = cluster.getInternalNodeClient()) {
            CloseIndexRequest closeIndexRequest = new CloseIndexRequest(indexName);
            CloseIndexResponse response = client.admin().indices().close(closeIndexRequest).actionGet();

            assertThat(response.isAcknowledged(), is(true));
            assertThat(response.isShardsAcknowledged(), is(true));
            assertThat(cluster, indexStateIsEqualTo(indexName, IndexMetadata.State.CLOSE));
        }
    }

    public static void createMapping(LocalCluster cluster, String indexName, Map<String, Object> indexMapping) {
        try (Client client = cluster.getInternalNodeClient()) {
            var response = client.admin().indices().putMapping(new PutMappingRequest(indexName).source(indexMapping)).actionGet();

            assertThat(response.isAcknowledged(), is(true));
        }
    }
}
