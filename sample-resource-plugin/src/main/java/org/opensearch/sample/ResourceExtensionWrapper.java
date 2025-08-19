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

import org.opensearch.common.inject.Inject;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

import java.util.Set;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

public class ResourceExtensionWrapper {

    @Inject(optional = true)
    public SampleResourceExtension extension;

    /**
     * Returns the assigned resource sharing client
     */
    public ResourceSharingClient getResourceSharingClient() {
        if (extension == null) {
            return null;
        }
        return extension.getResourceSharingClient();
    }
}
