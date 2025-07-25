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

import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Responsible for parsing the XContent into a SampleResource object.
 */
public class SampleResourceExtension implements ResourceSharingExtension {
    private ResourceSharingClient client;

    @Override
    public Set<ResourceProvider> getResourceProviders() {
        return Set.of(new ResourceProvider(SampleResource.class.getCanonicalName(), RESOURCE_INDEX_NAME));
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
        this.client = resourceSharingClient;
    }

    @Override
    public ResourceSharingClient getResourceSharingClient() {
        return this.client;
    }
}
