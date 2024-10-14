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

import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.threadpool.ThreadPool;

public class ResourceManagementRepository {

    private static final Logger LOGGER = LogManager.getLogger(ConfigurationRepository.class);

    private final Client client;

    private final ThreadPool threadPool;

    private final ResourceSharingIndexHandler resourceSharingIndexHandler;

    protected ResourceManagementRepository(
        final ThreadPool threadPool,
        final Client client,
        final ResourceSharingIndexHandler resourceSharingIndexHandler
    ) {
        this.client = client;
        this.threadPool = threadPool;
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
    }

    public static ResourceManagementRepository create(
        Settings settings,
        final ThreadPool threadPool,
        Client client,
        ResourceSharingIndexHandler resourceSharingIndexHandler
    ) {

        return new ResourceManagementRepository(threadPool, client, resourceSharingIndexHandler);
    }

    public void createResourceSharingIndexIfAbsent() {
        // TODO check if this should be wrapped in an atomic completable future

        this.resourceSharingIndexHandler.createResourceSharingIndexIfAbsent(() -> null);
    }

}
