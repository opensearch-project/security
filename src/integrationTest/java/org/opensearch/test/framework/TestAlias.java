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

package org.opensearch.test.framework;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.transport.client.Client;

public class TestAlias implements TestIndexLike {

    private final String name;
    private final ImmutableSet<TestIndexLike> indices;
    private Set<String> documentIds;
    private Map<String, TestData.TestDocument> documents;
    private TestIndexLike writeIndex;

    public TestAlias(String name, TestIndexLike... indices) {
        this.name = name;
        this.indices = ImmutableSet.copyOf(indices);
    }

    public TestAlias writeIndex(TestIndexLike writeIndex) {
        this.writeIndex = writeIndex;
        return this;
    }

    @Override
    public String toString() {
        return "Test alias name '" + name + "'";
    }

    public void create(Client client) {
        client.admin()
            .indices()
            .aliases(
                new IndicesAliasesRequest().addAliasAction(
                    IndicesAliasesRequest.AliasActions.add().indices(getIndexNamesAsArray()).alias(name)
                )
            )
            .actionGet();

        if (writeIndex != null) {
            client.admin()
                .indices()
                .aliases(
                    new IndicesAliasesRequest().addAliasAction(
                        IndicesAliasesRequest.AliasActions.add().index(writeIndex.name()).alias(name).writeIndex(true)
                    )
                )
                .actionGet();
        }
    }

    @Override
    public String name() {
        return name;
    }

    public ImmutableSet<TestIndexLike> getIndices() {
        return indices;
    }

    public String[] getIndexNamesAsArray() {
        return indices.stream().map(TestIndexLike::name).collect(Collectors.toSet()).toArray(new String[0]);
    }

    @Override
    public Set<String> documentIds() {
        Set<String> result = this.documentIds;

        if (result == null) {
            result = new HashSet<>();
            for (TestIndexLike testIndex : this.indices) {
                result.addAll(testIndex.documentIds());
            }

            result = Collections.unmodifiableSet(result);
            this.documentIds = result;
        }

        return result;
    }

    @Override
    public Map<String, TestData.TestDocument> documents() {
        Map<String, TestData.TestDocument> result = this.documents;

        if (result == null) {
            result = new HashMap<>();
            for (TestIndexLike testIndex : this.indices) {
                result.putAll(testIndex.documents());
            }

            result = Collections.unmodifiableMap(result);
            this.documents = result;
        }

        return result;
    }
}
