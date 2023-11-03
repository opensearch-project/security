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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class AuthFailureListeners implements ToXContentObject {

    private Map<String, RateLimiting> limits = new LinkedHashMap<>();

    public AuthFailureListeners addRateLimit(RateLimiting rateLimiting) {
        Objects.requireNonNull(rateLimiting, "Rate limiting is required");
        limits.put(rateLimiting.getName(), rateLimiting);
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        for (Map.Entry<String, RateLimiting> entry : limits.entrySet()) {
            xContentBuilder.field(entry.getKey(), entry.getValue());
        }
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
