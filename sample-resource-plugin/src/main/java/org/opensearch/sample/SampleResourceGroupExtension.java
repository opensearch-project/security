package org.opensearch.sample;

import java.util.Set;

import org.opensearch.sample.client.ResourceSharingClientAccessor;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_GROUP_TYPE;
import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Responsible for parsing the XContent into a SampleResourceGroup object.
 */
public class SampleResourceGroupExtension implements ResourceSharingExtension {

    @Override
    public Set<ResourceProvider> getResourceProviders() {
        return Set.of(new ResourceProvider() {
            @Override
            public String resourceType() {
                return RESOURCE_GROUP_TYPE;
            }

            @Override
            public String resourceIndexName() {
                return RESOURCE_INDEX_NAME;
            }

            @Override
            public String typeField() {
                return "resource_type";
            }
        });
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(resourceSharingClient);
    }
}
