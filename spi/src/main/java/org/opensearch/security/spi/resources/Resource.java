/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.io.IOException;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.ToXContentFragment;

/**
 * Marker interface for all resources
 */
public interface Resource extends NamedWriteable, ToXContentFragment {
    /**
     * Get the resource name
     * @return resource name
     */
    String getResourceName();

    // For de-serialization
    Resource readFrom(StreamInput in) throws IOException;

    // TODO: Next iteration, check if getResourceType() should be implemented
}
