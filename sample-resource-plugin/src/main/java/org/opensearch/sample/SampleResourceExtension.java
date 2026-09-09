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

package org.opensearch.sample;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.opensearch.sample.client.ResourceSharingClientAccessor;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.RESOURCE_TYPE;

/**
 * Responsible for parsing the XContent into a SampleResource object.
 */
public class SampleResourceExtension implements ResourceSharingExtension {

    @Override
    public Set<ResourceProvider> getResourceProviders() {
        return Set.of(new ResourceProvider() {
            @Override
            public String resourceType() {
                return RESOURCE_TYPE;
            }

            @Override
            public String resourceIndexName() {
                return RESOURCE_INDEX_NAME;
            }

            @Override
            public String typeField() {
                return "resource_type";
            }

            @Override
            public String parentType() {
                return RESOURCE_GROUP_TYPE;
            }

            @Override
            public String parentIdField() {
                return "group_id";
            }
            // workspacesField() defaults to "workspaces" — no override needed.
        });
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(resourceSharingClient);
    }

    /**
     * Sample resolver: maps each of the user's security roles to a workspace id ({@code ws-<role>}). Security roles
     * are server-resolved (not user-assertable), satisfying the SPI's trusted-source contract.
     */
    @Override
    public Set<String> resolveWorkspacesForUser(String username, Set<String> securityRoles, Set<String> backendRoles) {
        if (securityRoles == null || securityRoles.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> workspaces = new HashSet<>();
        for (String role : securityRoles) {
            workspaces.add("ws-" + role);
        }
        return workspaces;
    }
}
