/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

/**
 * This record class represents a resource provider.
 * It holds information about the resource type, resource index name, and a resource parser.
 *
 * @opensearch.experimental
 */
public interface ResourceProvider {

    String resourceType();

    String resourceIndexName();

}
