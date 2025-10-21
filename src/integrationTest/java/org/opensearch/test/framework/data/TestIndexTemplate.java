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

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.transport.client.Client;

public class TestIndexTemplate {
    public static final TestIndexTemplate DATA_STREAM_MINIMAL = new TestIndexTemplate("test_index_template_data_stream_minimal", "ds_*")
        .dataStream()
        .composedOf(TestComponentTemplate.DATA_STREAM_MINIMAL);

    private final String name;
    private final ImmutableList<String> indexPatterns;
    private Object dataStream;
    private ImmutableList<TestComponentTemplate> composedOf = ImmutableList.of();
    private int priority = 0;

    public TestIndexTemplate(String name, String... indexPatterns) {
        this.name = name;
        this.indexPatterns = ImmutableList.copyOf(indexPatterns);
    }

    public TestIndexTemplate dataStream() {
        this.dataStream = ImmutableMap.of();
        return this;
    }

    public TestIndexTemplate dataStream(String k, Object v) {
        this.dataStream = ImmutableMap.of(k, v);
        return this;
    }

    public TestIndexTemplate composedOf(TestComponentTemplate... composedOf) {
        this.composedOf = ImmutableList.copyOf(composedOf);
        return this;
    }

    public TestIndexTemplate priority(int priority) {
        this.priority = priority;
        return this;
    }

    public String getName() {
        return name;
    }

    public List<TestComponentTemplate> getComposedOf() {
        return composedOf;
    }

    public void create(Client client) throws Exception {
        try (XContentBuilder builder = JsonXContent.contentBuilder().map(getAsMap())) {
            try (
                XContentParser parser = JsonXContent.jsonXContent.createParser(
                    NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE,
                    BytesReference.bytes(builder).streamInput()
                )
            ) {
                client.admin()
                    .indices()
                    .execute(
                        PutComposableIndexTemplateAction.INSTANCE,
                        new PutComposableIndexTemplateAction.Request(name).indexTemplate(ComposableIndexTemplate.parse(parser))
                    )
                    .actionGet();
            }
        }
    }

    public Map<String, ?> getAsMap() {
        return ImmutableMap.of(
            "index_patterns",
            indexPatterns,
            "priority",
            priority,
            "data_stream",
            dataStream,
            "composed_of",
            composedOf.stream().map(TestComponentTemplate::getName).collect(Collectors.toList())
        );
    }
}
