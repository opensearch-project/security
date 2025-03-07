/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.common.resources;

import org.opensearch.security.spi.resources.ResourceParser;

/**
 * This record class represents a resource provider.
 * It holds information about the resource type, resource index name, and a resource parser.
 */
public record ResourceProvider(String resourceType, String resourceIndexName, ResourceParser resourceParser) {

}
