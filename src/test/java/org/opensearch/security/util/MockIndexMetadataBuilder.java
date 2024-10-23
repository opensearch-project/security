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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;

import org.opensearch.Version;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.Index;

/**
 * Creates mocks of org.opensearch.cluster.metadata.IndexAbstraction maps. Useful for unit testing code which
 * operates on index metadata.
 *
 * TODO: This is the evil twin of the same class in the integrationTest module. Possibly tests depending on this
 * should be moved to the integrationTest module?
 */
public class MockIndexMetadataBuilder {

    private final static Settings INDEX_SETTINGS = Settings.builder()
        .put(IndexMetadata.SETTING_INDEX_VERSION_CREATED.getKey(), Version.CURRENT)
        .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
        .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 1)
        .build();

    private Map<String, IndexAbstraction> nameToIndexAbstractionMap = new HashMap<>();
    private Map<String, IndexMetadata> nameToIndexMetadataMap = new HashMap<>();
    private Map<String, Set<String>> indicesToAliases = new HashMap<>();
    private Map<String, Set<String>> aliasesToIndices = new HashMap<>();

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

    public ImmutableMap<String, IndexAbstraction> build() {
        Map<String, AliasMetadata> aliasMetadataMap = new HashMap<>();

        for (Map.Entry<String, Set<String>> aliasEntry : this.aliasesToIndices.entrySet()) {
            String alias = aliasEntry.getKey();
            AliasMetadata aliasMetadata = AliasMetadata.builder(alias).build();
            aliasMetadataMap.put(alias, aliasMetadata);
        }

        for (Map.Entry<String, Set<String>> indexEntry : this.indicesToAliases.entrySet()) {
            String index = indexEntry.getKey();
            Set<String> aliases = indexEntry.getValue();

            IndexMetadata.Builder indexMetadataBuilder = IndexMetadata.builder(index).settings(INDEX_SETTINGS);

            for (String alias : aliases) {
                indexMetadataBuilder.putAlias(aliasMetadataMap.get(alias));
            }

            IndexMetadata indexMetadata = indexMetadataBuilder.build();
            nameToIndexMetadataMap.put(index, indexMetadata);
            nameToIndexAbstractionMap.put(index, new IndexAbstraction.Index(indexMetadata));
        }

        for (Map.Entry<String, Set<String>> aliasEntry : this.aliasesToIndices.entrySet()) {
            String alias = aliasEntry.getKey();
            Set<String> indices = aliasEntry.getValue();
            AliasMetadata aliasMetadata = aliasMetadataMap.get(alias);

            String firstIndex = indices.iterator().next();
            indices.remove(firstIndex);

            IndexMetadata firstIndexMetadata = nameToIndexMetadataMap.get(firstIndex);
            IndexAbstraction.Alias indexAbstraction = new IndexAbstraction.Alias(aliasMetadata, firstIndexMetadata);

            for (String index : indices) {
                indexAbstraction.getIndices().add(nameToIndexMetadataMap.get(index));
            }

            nameToIndexAbstractionMap.put(alias, indexAbstraction);
        }

        return ImmutableMap.copyOf(this.nameToIndexAbstractionMap);
    }

    public MockIndexMetadataBuilder index(String index) {
        if (!this.indicesToAliases.containsKey(index)) {
            this.indicesToAliases.put(index, new HashSet<>());
        }
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
        }

        DataStream dataStreamMetadata = new DataStream(dataStream, new DataStream.TimestampField("@timestamp"), backingIndices);
        IndexAbstraction.DataStream dataStreamIndexAbstraction = new IndexAbstraction.DataStream(
            dataStreamMetadata,
            backingIndices.stream().map(i -> getIndexMetadata(i.getName())).collect(Collectors.toList())
        );
        this.nameToIndexAbstractionMap.put(dataStream, dataStreamIndexAbstraction);

        for (Index backingIndex : backingIndices) {
            this.nameToIndexAbstractionMap.put(
                backingIndex.getName(),
                new IndexAbstraction.Index(getIndexMetadata(backingIndex.getName()), dataStreamIndexAbstraction)
            );
        }

        return this;
    }

    private IndexMetadata getIndexMetadata(String index) {
        IndexMetadata result = this.nameToIndexMetadataMap.get(index);

        if (result == null) {
            result = IndexMetadata.builder(index)
                .settings(Settings.builder().put(IndexMetadata.SETTING_INDEX_VERSION_CREATED.getKey(), Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(1)
                .build();
            this.nameToIndexMetadataMap.put(index, result);
        }

        return result;
    }

    public class AliasBuilder {
        private String alias;

        private AliasBuilder(String alias) {
            this.alias = alias;
        }

        public MockIndexMetadataBuilder of(String firstIndex, String... moreIndices) {
            MockIndexMetadataBuilder.this.indicesToAliases.computeIfAbsent(firstIndex, (k) -> new HashSet<>()).add(this.alias);

            Set<String> indices = new HashSet<>();
            indices.add(firstIndex);

            for (String index : moreIndices) {
                MockIndexMetadataBuilder.this.indicesToAliases.computeIfAbsent(index, (k) -> new HashSet<>()).add(this.alias);
                indices.add(index);
            }

            MockIndexMetadataBuilder.this.aliasesToIndices.put(this.alias, indices);

            return MockIndexMetadataBuilder.this;
        }
    }
}
