/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.inject.Inject;
import org.opensearch.security.spi.resources.fallback.DefaultResourceAccessControlPlugin;

/**
 * Service to get the current ResourceSharingExtension to perform authorization.
 *
 * @opensearch.experimental
 */
public class ResourceService {
    private static final Logger log = LogManager.getLogger(ResourceService.class);

    private final ResourceAccessControlPlugin resourceACPlugin;

    @Inject
    public ResourceService(final List<ResourceAccessControlPlugin> resourceACPlugins) {

        if (resourceACPlugins.isEmpty()) {
            log.info("Security plugin disabled: Using DefaultResourceAccessControlPlugin");
            resourceACPlugin = new DefaultResourceAccessControlPlugin();
        } else if (resourceACPlugins.size() == 1) {
            log.info("Security plugin enabled: Using OpenSearchSecurityPlugin");
            resourceACPlugin = resourceACPlugins.get(0);
        } else {
            throw new OpenSearchException(
                "Multiple resource access control plugins are not supported, found: "
                    + resourceACPlugins.stream().map(Object::getClass).map(Class::getName).collect(Collectors.joining(","))
            );
        }
    }

    /**
     * Gets the ResourceAccessControlPlugin in-effect to perform authorization
     */
    public ResourceAccessControlPlugin getResourceAccessControlPlugin() {
        return resourceACPlugin;
    }
}
