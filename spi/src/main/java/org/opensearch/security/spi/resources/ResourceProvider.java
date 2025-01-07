/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

public class ResourceProvider {
    private final String resourceType;
    private final String resourceIndexName;
    private final ResourceParser resourceParser;

    public ResourceParser getResourceParser() {
        return resourceParser;
    }

    public String getResourceIndexName() {
        return resourceIndexName;
    }

    public String getResourceType() {
        return resourceType;
    }

    public ResourceProvider(String resourceType, String resourceIndexName, ResourceParser resourceParser) {
        this.resourceType = resourceType;
        this.resourceIndexName = resourceIndexName;
        this.resourceParser = resourceParser;
    }
}
