/*
 * Copyright 2021-2022 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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

import java.util.Map;
import java.util.Set;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.transport.client.Client;

public class TestIndex implements TestIndexOrAliasOrDatastream {

    private final String name;
    private final Settings settings;
    private final TestData testData;

    public TestIndex(String name, Settings settings, TestData testData) {
        this.name = name;
        this.settings = settings;
        this.testData = testData;
    }

    @Override
    public void create(Client client) {
        if (testData != null) {
            testData.createIndex(client, name, settings);
        } else {
            client.admin().indices().create(new CreateIndexRequest(name).settings(settings)).actionGet();
        }
    }

    @Override
    public void delete(Client client) {
        try {
            client.admin().indices().delete(new DeleteIndexRequest(name)).actionGet();
        } catch (IndexNotFoundException e) {
            // It is fine if the object to be deleted does not exist
        }
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Set<String> documentIds() {
        return testData.documents().allIds();
    }

    @Override
    public Map<String, TestData.TestDocument> documents() {
        return testData.documents().allDocs();
    }

    public TestData.TestDocument anyDocument() {
        return testData.anyDocument();
    }

    public static Builder name(String name) {
        return new Builder().name(name);
    }

    public static class Builder {
        private String name;
        private Settings.Builder settings = Settings.builder();
        private TestData.Builder testDataBuilder = new TestData.Builder();
        private TestData testData;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder setting(String name, int value) {
            settings.put(name, value);
            return this;
        }

        public Builder shards(int value) {
            settings.put("index.number_of_shards", value);
            return this;
        }

        public Builder hidden() {
            settings.put("index.hidden", true);
            return this;
        }

        public Builder data(TestData testData) {
            this.testData = testData;
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

        public TestIndex build() {
            if (testData == null) {
                testData = testDataBuilder.get();
            }

            return new TestIndex(name, settings.build(), testData);
        }

    }

    /**
     * This returns a magic TestIndexLike object symbolizing the internal OpenSearch security
     * config index. This is supposed to be used with the IndexApiResponseMatchers.
     */
    public static TestIndexOrAliasOrDatastream openSearchSecurityConfigIndex() {
        return OPEN_SEARCH_SECURITY_CONFIG_INDEX;
    }

    private final static TestIndexOrAliasOrDatastream OPEN_SEARCH_SECURITY_CONFIG_INDEX = new TestIndexOrAliasOrDatastream() {

        @Override
        public String name() {
            return ".opendistro_security";
        }

        @Override
        public Map<String, TestData.TestDocument> documents() {
            return null;
        }

        @Override
        public void create(Client client) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void delete(Client client) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> documentIds() {
            return null;
        }
    };

}
