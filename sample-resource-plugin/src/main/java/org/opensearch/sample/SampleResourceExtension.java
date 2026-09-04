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

            @Override
            public String workspacesField() {
                return "workspaces";
            }
        });
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(resourceSharingClient);
    }

    /**
     * Test-only workspace-membership resolver. Maps a user's <em>security roles</em> to a deterministic workspace ID
     * ({@code ws-<role>}), simulating a trusted server-set source. Roles are resolved by the security plugin at
     * authc time, so they are not user-assertable — matching the SPI contract.
     *
     * <p>A real workspace-owning plugin would replace this with a lookup against its own authoritative store
     * (populated at authc time or cached in memory), never with values derived from user-influenceable inputs.
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
