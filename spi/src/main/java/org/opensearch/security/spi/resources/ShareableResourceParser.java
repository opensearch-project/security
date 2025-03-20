/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.io.IOException;

import org.opensearch.core.xcontent.XContentParser;

/**
 * Interface for parsing shareable resources from XContentParser
 * @param <T> the type of resource to be parsed
 *
 * @opensearch.experimental
 */
public interface ShareableResourceParser<T extends ShareableResource> {
    /**
     * Parse source bytes supplied by the parser to a desired ShareableResource type
     * @param parser to parser bytes-ref json input
     * @return the parsed object of ShareableResource type
     * @throws IOException if something went wrong while parsing
     */
    T parseXContent(XContentParser parser) throws IOException;
}
