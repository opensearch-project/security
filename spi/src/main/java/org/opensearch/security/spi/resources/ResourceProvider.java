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

    /**
     * JSON pointer path (dot-notation is also accepted for backward compatibility) to the field
     * containing the resource owner's username on documents of this type. Used by the
     * {@code POST /_plugins/_security/api/resources/migrate} endpoint to attribute legacy docs
     * without requiring a single global {@code username_path} in the request payload.
     *
     * <p>When multiple providers register on the same resource index, each provider may declare a
     * type-specific path (for example, {@code monitor.user.name} and {@code workflow.user.name});
     * the migrate endpoint resolves the type first via {@link #typeField()} and then reads the
     * owner from the matching provider's path.
     *
     * <p>Returning {@code null} (the default) preserves the legacy behavior of falling back to the
     * request-level {@code username_path}.
     *
     * @return the JSON pointer path (with or without a leading {@code /}) or {@code null} if this
     *         provider does not declare a per-type owner path
     */
    default String ownerNamePath() {
        return null;
    }

    /**
     * JSON pointer path to the field containing the resource owner's backend roles on documents of
     * this type. See {@link #ownerNamePath()} for the resolution rules and fallback semantics.
     *
     * @return the JSON pointer path (with or without a leading {@code /}) or {@code null} if this
     *         provider does not declare a per-type backend-roles path
     */
    default String ownerBackendRolesPath() {
        return null;
    }

}
