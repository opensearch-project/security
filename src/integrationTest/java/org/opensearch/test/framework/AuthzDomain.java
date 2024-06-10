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

/**
* The class represents authorization domain
*/
public class AuthzDomain implements ToXContentObject {

    private final String id;

    private String description;

    private boolean httpEnabled;

    private AuthorizationBackend authorizationBackend;

    public AuthzDomain(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public AuthzDomain description(String description) {
        this.description = description;
        return this;
    }

    public AuthzDomain httpEnabled(boolean httpEnabled) {
        this.httpEnabled = httpEnabled;
        return this;
    }

    public AuthzDomain authorizationBackend(AuthorizationBackend authorizationBackend) {
        this.authorizationBackend = authorizationBackend;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("description", description);
        xContentBuilder.field("http_enabled", httpEnabled);
        xContentBuilder.field("authorization_backend", authorizationBackend);
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
