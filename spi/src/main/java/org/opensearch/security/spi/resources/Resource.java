/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.xcontent.ToXContentFragment;

/**
 * Marker interface for all resources
 */
public interface Resource extends NamedWriteable, ToXContentFragment {
    /**
     * Abstract method to get the resource name.
     * Must be implemented by plugins defining resources.
     *
     * @return resource name
     */
    String getResourceName();
}
