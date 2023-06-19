/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class AuthorizationBackend implements ToXContentObject {
    private final String type;
    private Supplier<Map<String, Object>> config;

    public AuthorizationBackend(String type) {
        this.type = type;
    }

    public AuthorizationBackend config(Map<String, Object> ldapConfig) {
        return config(() -> ldapConfig);
    }

    public AuthorizationBackend config(Supplier<Map<String, Object>> ldapConfigSupplier) {
        this.config = Objects.requireNonNull(ldapConfigSupplier, "Configuration supplier is required");
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("type", type);
        xContentBuilder.field("config", config.get());
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
