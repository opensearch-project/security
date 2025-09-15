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

import com.google.common.collect.ImmutableMap;

import org.opensearch.action.admin.indices.template.put.PutComponentTemplateAction;
import org.opensearch.cluster.metadata.ComponentTemplate;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.transport.client.Client;

public class TestComponentTemplate {
    public static TestComponentTemplate DATA_STREAM_MINIMAL = new TestComponentTemplate(
        "test_component_template_data_stream_minimal",
        new TestMapping(new TestMapping.Property("@timestamp", "date", "date_optional_time||epoch_millis"))
    );

    private final String name;
    private final TestMapping mapping;

    public TestComponentTemplate(String name, TestMapping mapping) {
        this.name = name;
        this.mapping = mapping;
    }

    public String getName() {
        return name;
    }

    public TestMapping getMapping() {
        return mapping;
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
                        PutComponentTemplateAction.INSTANCE,
                        new PutComponentTemplateAction.Request(name).componentTemplate(ComponentTemplate.parse(parser))
                    )
                    .actionGet();
            }
        }
    }

    public Map<String, ?> getAsMap() {
        return ImmutableMap.of("template", ImmutableMap.of("mappings", mapping.getAsMap()));
    }
}
