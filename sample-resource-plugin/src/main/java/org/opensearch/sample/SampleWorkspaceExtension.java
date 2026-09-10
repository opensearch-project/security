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

import java.util.Set;

import org.opensearch.sample.client.ResourceSharingClientAccessor;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.sample.utils.Constants.WORKSPACE_TYPE;

/**
 * Registers {@code workspace} as a resource type so the write-path container fan-out
 * ({@code ResourceAccessHandler.checkContainers}) can be exercised: a resource inherits access from any workspace it
 * belongs to. Workspace records share the sample resource index, distinguished by {@code resource_type}; their access
 * levels (workspace_read_only/read_write/full_access) map to child actions in resource-access-levels.yml.
 */
public class SampleWorkspaceExtension implements ResourceSharingExtension {

    @Override
    public Set<ResourceProvider> getResourceProviders() {
        return Set.of(new ResourceProvider() {
            @Override
            public String resourceType() {
                return WORKSPACE_TYPE;
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
            public String workspacesField() {
                // A workspace does not itself belong to a workspace.
                return null;
            }
        });
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(resourceSharingClient);
    }
}
