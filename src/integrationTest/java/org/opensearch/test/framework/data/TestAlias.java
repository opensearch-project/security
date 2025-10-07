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

package org.opensearch.test.framework.data;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.rest.action.admin.indices.AliasesNotFoundException;
import org.opensearch.transport.client.Client;

public class TestAlias implements TestIndexOrAliasOrDatastream {

    private final String name;
    private final ImmutableSet<TestIndexOrAliasOrDatastream> indices;
    private final TestIndexOrAliasOrDatastream writeIndex;
    private final boolean hidden;

    private Set<String> documentIds;
    private Map<String, TestData.TestDocument> documents;

    public TestAlias(String name, TestIndexOrAliasOrDatastream... indices) {
        this.name = name;
        this.indices = ImmutableSet.copyOf(indices);
        this.writeIndex = null;
        this.hidden = false;
    }

    TestAlias(String name, ImmutableSet<TestIndexOrAliasOrDatastream> indices, TestIndexOrAliasOrDatastream writeIndex, boolean hidden) {
        this.name = name;
        this.indices = indices;
        this.writeIndex = writeIndex;
        this.hidden = hidden;
    }

    public TestAlias on(TestIndexOrAliasOrDatastream... indices) {
        return new TestAlias(this.name, ImmutableSet.copyOf(indices), this.writeIndex, this.hidden);
    }

    public TestAlias writeIndex(TestIndexOrAliasOrDatastream writeIndex) {
        return new TestAlias(this.name, this.indices, writeIndex, this.hidden);
    }

    public TestAlias hidden() {
        return new TestAlias(this.name, this.indices, this.writeIndex, true);
    }

    @Override
    public String toString() {
        return "Test alias '" + name + "'";
    }

    @Override
    public void create(Client client) {
        client.admin()
            .indices()
            .aliases(
                new IndicesAliasesRequest().addAliasAction(
                    IndicesAliasesRequest.AliasActions.add().indices(getIndexNamesAsArray()).alias(name).isHidden(hidden)
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
    public void delete(Client client) {
        try {
            client.admin()
                .indices()
                .aliases(new IndicesAliasesRequest().addAliasAction(IndicesAliasesRequest.AliasActions.remove().alias(name).indices("*")))
                .actionGet();
        } catch (AliasesNotFoundException e) {
            // It is fine if the alias to be deleted does not exist
        }
    }

    @Override
    public String name() {
        return name;
    }

    public ImmutableSet<TestIndexOrAliasOrDatastream> getIndices() {
        return indices;
    }

    public String[] getIndexNamesAsArray() {
        return indices.stream().map(TestIndexOrAliasOrDatastream::name).collect(Collectors.toSet()).toArray(new String[0]);
    }

    @Override
    public Set<String> documentIds() {
        Set<String> result = this.documentIds;

        if (result == null) {
            result = new HashSet<>();
            for (TestIndexOrAliasOrDatastream testIndex : this.indices) {
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
            for (TestIndexOrAliasOrDatastream testIndex : this.indices) {
                result.putAll(testIndex.documents());
            }

            result = Collections.unmodifiableMap(result);
            this.documents = result;
        }

        return result;
    }

    public static TestIndex.Builder name(String name) {
        return new TestIndex.Builder().name(name);
    }
}
