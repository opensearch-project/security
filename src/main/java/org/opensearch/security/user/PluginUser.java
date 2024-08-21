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

package org.opensearch.security.user;

import java.io.IOException;

import org.opensearch.core.common.io.stream.StreamInput;

public class PluginUser extends User {
    private static final long serialVersionUID = -4083322940729403322L;

    public PluginUser(StreamInput in) throws IOException {
        super(in);
    }

    /**
     * Create a new plugin user without roles and attributes
     *
     * @param name The username (must not be null or empty)
     * @throws IllegalArgumentException if name is null or empty
     */
    public PluginUser(final String name) {
        super(name, null, null);
    }
}
