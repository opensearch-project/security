/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.io.IOException;

public interface ResourceParser<T extends Resource> {
    /**
     * Parse stringified json input to a desired Resource type
     * @param source the stringified json input
     * @return the parsed object of Resource type
     * @throws IOException if something went wrong while parsing
     */
    T parse(String source) throws IOException;
}
