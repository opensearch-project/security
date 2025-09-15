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

import java.util.Map;
import java.util.Set;

import org.opensearch.action.admin.indices.datastream.CreateDataStreamAction;
import org.opensearch.action.admin.indices.datastream.DeleteDataStreamAction;
import org.opensearch.transport.client.Client;

public class TestDataStream implements TestIndexOrAliasOrDatastream {

    private final String name;
    private final TestData testData;
    private final int rolloverAfter;

    public TestDataStream(String name, TestData testData, int rolloverAfter) {
        this.name = name;
        this.testData = testData;
        this.rolloverAfter = rolloverAfter;
    }

    @Override
    public void create(Client client) {
        client.admin().indices().createDataStream(new CreateDataStreamAction.Request(name)).actionGet();
        testData.putDocuments(client, name, rolloverAfter);
    }

    @Override
    public void delete(Client client) {
        client.admin().indices().deleteDataStream(new DeleteDataStreamAction.Request(new String[] { name })).actionGet();
    }

    public String name() {
        return name;
    }

    public TestData testData() {
        return testData;
    }

    public static Builder name(String name) {
        return new Builder().name(name);
    }

    @Override
    public String toString() {
        return "Test data stream '" + name + '\'';
    }

    public static class Builder {
        private String name;
        private final TestData.Builder testDataBuilder = new TestData.Builder().timestampColumnName("@timestamp")
            .deletedDocumentFraction(0);
        private TestData testData;
        private int rolloverAfter = -1;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder data(TestData data) {
            this.testData = data;
            return this;
        }

        public Builder seed(int seed) {
            testDataBuilder.seed(seed);
            return this;
        }

        public Builder documentCount(int size) {
            testDataBuilder.documentCount(size);
            return this;
        }

        public Builder refreshAfter(int refreshAfter) {
            testDataBuilder.refreshAfter(refreshAfter);
            return this;
        }

        public Builder rolloverAfter(int rolloverAfter) {
            this.rolloverAfter = rolloverAfter;
            return this;
        }

        public TestDataStream build() {
            if (testData == null) {
                testData = testDataBuilder.get();
            }

            return new TestDataStream(name, testData, rolloverAfter);
        }
    }

    @Override
    public Set<String> documentIds() {
        return testData().getRetainedDocuments().keySet();
    }

    @Override
    public Map<String, TestData.TestDocument> documents() {
        return testData().getRetainedDocuments();
    }

}
