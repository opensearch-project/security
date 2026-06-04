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

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class ApiTokenConfig implements ToXContentObject {
    private Boolean enabled;

    public ApiTokenConfig enabled(Boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("enabled", enabled);
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
