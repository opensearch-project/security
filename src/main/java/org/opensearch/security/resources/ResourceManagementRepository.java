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

package org.opensearch.security.resources;

public class ResourceManagementRepository {

    private final ResourceSharingIndexHandler resourceSharingIndexHandler;

    protected ResourceManagementRepository(final ResourceSharingIndexHandler resourceSharingIndexHandler) {
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
    }

    public static ResourceManagementRepository create(ResourceSharingIndexHandler resourceSharingIndexHandler) {

        return new ResourceManagementRepository(resourceSharingIndexHandler);
    }

    /**
     * Creates the resource sharing index if it doesn't already exist.
     * This method is called during the initialization phase of the repository.
     * It ensures that the index is set up with the necessary mappings and settings
     * before any operations are performed on the index.
     */
    public void createResourceSharingIndexIfAbsent() {
        // TODO check if this should be wrapped in an atomic completable future

        this.resourceSharingIndexHandler.createResourceSharingIndexIfAbsent(() -> null);
    }

}
