/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

/**
 * This class determines a type of recipient a resource can be shared with.
 * An example type would be a user or a role.
 * This class is used to determine the type of recipient a resource can be shared with.
 *
 * @opensearch.experimental
 */
public record RecipientType(String type) {

    @Override
    public String toString() {
        return type;
    }
}
