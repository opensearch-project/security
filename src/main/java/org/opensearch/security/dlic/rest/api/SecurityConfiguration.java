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

import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class SecurityConfiguration {

    private final String resourceName;

    private final JsonNode requestContent;

    private final SecurityDynamicConfiguration<?> configuration;

    private SecurityConfiguration(final String resourceName, final SecurityDynamicConfiguration<?> configuration) {
        this(resourceName, null, configuration);
    }

    private SecurityConfiguration(
        final String resourceName,
        final JsonNode requestContent,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        this.resourceName = resourceName;
        this.requestContent = requestContent;
        this.configuration = configuration;
    }

    public SecurityDynamicConfiguration<?> configuration() {
        return configuration;
    }

    public JsonNode requestContent() {
        return requestContent;
    }

    public Object contentAsConfigObject() throws IOException {
        return Utils.toConfigObject(requestContent, configuration.getImplementingClass());
    }

    public JsonNode configurationAsJsonNode() throws IOException {
        return configurationAsJsonNode(false);
    }

    public JsonNode configurationAsJsonNode(final boolean omitDefaults) throws IOException {
        final BytesReference bytes = XContentHelper.toXContent(
            configuration,
            MediaTypeRegistry.JSON,
            new ToXContent.MapParams(Map.of("omit_defaults", Boolean.valueOf(omitDefaults).toString())),
            false
        );
        return DefaultObjectMapper.readTree(bytes.utf8ToString());
    }

    public SecurityDynamicConfiguration<?> resourceConfiguration() {
        if (resourceName != null) {
            configuration.removeOthers(resourceName);
        }
        return configuration;
    }

    public boolean resourceExists() {
        return configuration.exists(resourceName);
    }

    public SecurityDynamicConfiguration<?> deleteResource() {
        if (resourceName != null) {
            configuration.remove(resourceName);
        }
        return configuration;
    }

    public SecurityDynamicConfiguration<?> createOrUpdateResource() throws IOException {
        configuration.putCObject(resourceName, contentAsConfigObject());
        return configuration;
    }

    public Optional<String> maybeResourceName() {
        return Optional.ofNullable(resourceName);
    }

    public String resourceName() {
        return resourceName;
    }

    public static SecurityConfiguration of(final String resourceName, final SecurityDynamicConfiguration<?> configuration) {
        Objects.requireNonNull(configuration);
        return new SecurityConfiguration(resourceName, configuration);
    }

    public static SecurityConfiguration of(
        final String resourceName,
        final JsonNode requestContent,
        final SecurityDynamicConfiguration<?> configuration
    ) {
        Objects.requireNonNull(configuration);
        return new SecurityConfiguration(resourceName, requestContent, configuration);
    }

}
