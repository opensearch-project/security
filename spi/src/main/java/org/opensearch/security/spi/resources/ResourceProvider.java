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

    /**
     * Returns the name of the field representing the resource type in the resource document.
     *
     * @return the field name containing the resource type
     */
    default String typeField() {
        return null;
    }

    /**
     * Returns the type of the parent resource, if any, for hierarchical resources.
     *
     * @return the parent resource type
     */
    default String parentType() {
        return null;
    }

    /**
     * Returns the name of the field representing the parent resource ID in the child resource document.
     *
     * @return the field name containing the parent id
     */
    default String parentIdField() {
        return null;
    }

}
