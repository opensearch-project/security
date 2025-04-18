package org.opensearch.sample.nonsystemindex.plugin;

import java.util.Set;

import org.opensearch.sample.SampleResource;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import static org.opensearch.sample.nonsystemindex.plugin.ResourceNonSystemIndexPlugin.SAMPLE_NON_SYSTEM_INDEX_NAME;

public class ResourceNonSystemIndexExtension implements ResourceSharingExtension {
    @Override
    public Set<ResourceProvider> getResourceProviders() {
        return Set.of(new ResourceProvider(SampleResource.class.getCanonicalName(), SAMPLE_NON_SYSTEM_INDEX_NAME));
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {}
}
