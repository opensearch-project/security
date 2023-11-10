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

package org.opensearch.security.dlic.rest.api;

import java.util.Objects;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

public class SecurityConfiguration {

    private final String entityName;

    private final boolean entityExists;

    private final JsonNode requestContent;

    private final SecurityDynamicConfiguration<?> configuration;

    private SecurityConfiguration(
        final String entityName,
        final boolean entityExists,
        final JsonNode requestContent,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        this.entityName = entityName;
        this.entityExists = entityExists;
        this.requestContent = requestContent;
        this.configuration = configuration;
    }

    private SecurityConfiguration(
        final String entityName,
        final boolean entityExists,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        this(entityName, entityExists, null, configuration);
    }

    public SecurityDynamicConfiguration<?> configuration() {
        return configuration;
    }

    public boolean entityExists() {
        return entityExists;
    }

    public JsonNode requestContent() {
        return requestContent;
    }

    public Optional<String> maybeEntityName() {
        return Optional.ofNullable(entityName);
    }

    public String entityName() {
        return maybeEntityName().orElse("empty");
    }

    public static SecurityConfiguration of(final String entityName, final SecurityDynamicConfiguration<?> configuration) {
        Objects.requireNonNull(configuration, "configuration hasn't been set");
        return new SecurityConfiguration(entityName, configuration.exists(entityName), configuration);
    }

    public static SecurityConfiguration of(
        final JsonNode requestContent,
        final String entityName,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        Objects.requireNonNull(configuration, "configuration hasn't been set");
        Objects.requireNonNull(requestContent, "requestContent hasn't been set");
        return new SecurityConfiguration(entityName, configuration.exists(entityName), requestContent, configuration);
    }

}
