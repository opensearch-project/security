/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
package org.opensearch.security.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensearch.Version;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.Index;

/**
 * Creates mocks of org.opensearch.cluster.metadata.IndexAbstraction maps. Useful for unit testing code which
 * operates on index metadata.
 */
public class MockIndexMetadataBuilder {

    private static final Settings INDEX_SETTINGS = Settings.builder()
        .put(IndexMetadata.SETTING_INDEX_VERSION_CREATED.getKey(), Version.CURRENT)
        .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
        .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 1)
        .build();

    private Metadata.Builder delegate = new Metadata.Builder();
    private Map<String, IndexMetadata.Builder> nameToIndexMetadataBuilderMap = new HashMap<>();

    public static MockIndexMetadataBuilder indices(String... indices) {
        MockIndexMetadataBuilder builder = new MockIndexMetadataBuilder();

        for (String index : indices) {
            builder.index(index);
        }

        return builder;
    }

    public static MockIndexMetadataBuilder dataStreams(String... dataStreams) {
        MockIndexMetadataBuilder builder = new MockIndexMetadataBuilder();

        for (String dataStream : dataStreams) {
            builder.dataStream(dataStream);
        }

        return builder;
    }

    public Metadata build() {
        for (IndexMetadata.Builder indexMetadataBuilder : nameToIndexMetadataBuilderMap.values()) {
            this.delegate.put(indexMetadataBuilder);
        }

        return this.delegate.build();
    }

    public MockIndexMetadataBuilder index(String indexName) {
        return index(indexName, IndexMetadata.State.OPEN);
    }

    public MockIndexMetadataBuilder index(String indexName, IndexMetadata.State state) {
        getIndexMetadataBuilder(indexName, state);
        return this;
    }

    public AliasBuilder alias(String alias) {
        return new AliasBuilder(alias);
    }

    public MockIndexMetadataBuilder dataStream(String dataStream) {
        return dataStream(dataStream, 3);
    }

    public MockIndexMetadataBuilder dataStream(String dataStream, int generations) {
        List<Index> backingIndices = new ArrayList<>();

        for (int i = 1; i <= generations; i++) {
            String backingIndexName = DataStream.getDefaultBackingIndexName(dataStream, i);
            backingIndices.add(new Index(backingIndexName, backingIndexName));
            getIndexMetadataBuilder(backingIndexName, IndexMetadata.State.OPEN);
        }

        DataStream dataStreamMetadata = new DataStream(dataStream, new DataStream.TimestampField("@timestamp"), backingIndices);
        this.delegate.put(dataStreamMetadata);

        return this;
    }

    private IndexMetadata.Builder getIndexMetadataBuilder(String indexName, IndexMetadata.State state) {
        IndexMetadata.Builder result = this.nameToIndexMetadataBuilderMap.get(indexName);

        if (result != null) {
            return result;
        }

        result = new IndexMetadata.Builder(indexName).state(state)
            .settings(Settings.builder().put(INDEX_SETTINGS).put(IndexMetadata.SETTING_INDEX_UUID, indexName).build());

        this.nameToIndexMetadataBuilderMap.put(indexName, result);

        return result;
    }

    public class AliasBuilder {
        private String aliasName;

        private AliasBuilder(String alias) {
            this.aliasName = alias;
        }

        public MockIndexMetadataBuilder of(String... indices) {
            AliasMetadata aliasMetadata = new AliasMetadata.Builder(aliasName).build();

            for (String index : indices) {
                IndexMetadata.Builder indexMetadataBuilder = getIndexMetadataBuilder(index, IndexMetadata.State.OPEN);
                indexMetadataBuilder.putAlias(aliasMetadata);
            }

            return MockIndexMetadataBuilder.this;
        }
    }
}
