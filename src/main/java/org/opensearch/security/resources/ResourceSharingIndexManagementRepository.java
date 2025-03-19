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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class is responsible for managing the resource sharing index.
 * It provides methods to create the index if it doesn't exist.
 *
 * @opensearch.experimental
 */
public class ResourceSharingIndexManagementRepository {

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexManagementRepository.class);

    private final ResourceSharingIndexHandler resourceSharingIndexHandler;
    private final boolean resourceSharingEnabled;

    protected ResourceSharingIndexManagementRepository(
        final ResourceSharingIndexHandler resourceSharingIndexHandler,
        boolean isResourceSharingEnabled
    ) {
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
        this.resourceSharingEnabled = isResourceSharingEnabled;
    }

    public static ResourceSharingIndexManagementRepository create(
        ResourceSharingIndexHandler resourceSharingIndexHandler,
        boolean isResourceSharingEnabled
    ) {
        return new ResourceSharingIndexManagementRepository(resourceSharingIndexHandler, isResourceSharingEnabled);
    }

    /**
     * Creates the resource sharing index if it doesn't already exist.
     * This method is called during the initialization phase of the repository.
     * It ensures that the index is set up with the necessary mappings and settings
     * before any operations are performed on the index.
     */
    public void createResourceSharingIndexIfAbsent() {
        // TODO check if this should be wrapped in an atomic completable future
        if (resourceSharingEnabled) {
            LOGGER.debug("Attempting to create Resource Sharing index");
            this.resourceSharingIndexHandler.createResourceSharingIndexIfAbsent(() -> null);
        }

    }
}
