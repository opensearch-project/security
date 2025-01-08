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
public abstract class Resource implements NamedWriteable, ToXContentFragment {
    /**
     * Abstract method to get the resource name.
     * Must be implemented by subclasses.
     *
     * @return resource name
     */
    public abstract String getResourceName();

    /**
     * Enforces that all subclasses have a constructor accepting StreamInput.
     */
    protected Resource(StreamInput in) throws IOException {}
}
