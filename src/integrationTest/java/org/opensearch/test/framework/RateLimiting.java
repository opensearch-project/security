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
import java.util.Objects;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class RateLimiting implements ToXContentObject {

    private final String name;
    private String type;
    private String authenticationBackend;
    private Integer allowedTries;
    private Integer timeWindowSeconds;
    private Integer blockExpirySeconds;
    private Integer maxBlockedClients;
    private Integer maxTrackedClients;

    public String getName() {
        return name;
    }

    public RateLimiting(String name) {
        this.name = Objects.requireNonNull(name, "Rate limit name is required.");
    }

    public RateLimiting type(String type) {
        this.type = type;
        return this;
    }

    public RateLimiting authenticationBackend(String authenticationBackend) {
        this.authenticationBackend = authenticationBackend;
        return this;
    }

    public RateLimiting allowedTries(Integer allowedTries) {
        this.allowedTries = allowedTries;
        return this;
    }

    public RateLimiting timeWindowSeconds(Integer timeWindowSeconds) {
        this.timeWindowSeconds = timeWindowSeconds;
        return this;
    }

    public RateLimiting blockExpirySeconds(Integer blockExpirySeconds) {
        this.blockExpirySeconds = blockExpirySeconds;
        return this;
    }

    public RateLimiting maxBlockedClients(Integer maxBlockedClients) {
        this.maxBlockedClients = maxBlockedClients;
        return this;
    }

    public RateLimiting maxTrackedClients(Integer maxTrackedClients) {
        this.maxTrackedClients = maxTrackedClients;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("type", type);
        xContentBuilder.field("authentication_backend", authenticationBackend);
        xContentBuilder.field("allowed_tries", allowedTries);
        xContentBuilder.field("time_window_seconds", timeWindowSeconds);
        xContentBuilder.field("block_expiry_seconds", blockExpirySeconds);
        xContentBuilder.field("max_blocked_clients", maxBlockedClients);
        xContentBuilder.field("max_tracked_clients", maxTrackedClients);
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
