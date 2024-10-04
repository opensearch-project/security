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

import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.CreatedBy;
import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.accesscontrol.resources.ResourceSharing;
import org.opensearch.accesscontrol.resources.ShareWith;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class ResourceAccessHandler {
    private static final Logger LOGGER = LogManager.getLogger(ResourceAccessHandler.class);

    private final ThreadContext threadContext;

    public ResourceAccessHandler(final ThreadPool threadPool) {
        super();
        this.threadContext = threadPool.getThreadContext();
    }

    public Map<String, List<String>> listAccessibleResources() {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Listing accessible resource for: {}", user.getName());

        // TODO add concrete implementation
        return Map.of();
    }

    public List<String> listAccessibleResourcesForPlugin(String systemIndex) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Listing accessible resource within a system index {} for : {}", systemIndex, user.getName());

        // TODO add concrete implementation
        return List.of();
    }

    public boolean hasPermission(String resourceId, String systemIndexName, String scope) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Checking if {} has {} permission to resource {}", user.getName(), scope, resourceId);

        // TODO add concrete implementation
        return false;
    }

    public ResourceSharing shareWith(String resourceId, String systemIndexName, ShareWith shareWith) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Sharing resource {} created by {} with {}", resourceId, user, shareWith);

        // TODO add concrete implementation
        CreatedBy c = new CreatedBy("", null);
        return new ResourceSharing(systemIndexName, resourceId, c, shareWith);
    }

    public ResourceSharing revokeAccess(String resourceId, String systemIndexName, Map<EntityType, List<String>> revokeAccess) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Revoking access to resource {} created by {} for {}", resourceId, user.getName(), revokeAccess);

        // TODO add concrete implementation
        return null;
    }

    public boolean deleteResourceSharingRecord(String resourceId, String systemIndexName) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Deleting resource sharing record for resource {} in {} created by {}", resourceId, systemIndexName, user.getName());

        // TODO add concrete implementation
        return false;
    }

    public boolean deleteAllResourceSharingRecordsForCurrentUser() {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        LOGGER.info("Deleting all resource sharing records for resource {}", user.getName());

        // TODO add concrete implementation
        return false;
    }

}
