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

package org.opensearch.security.privileges;

import com.google.common.collect.ImmutableSet;

import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.user.User;

/**
 * A general interface for components that map users to their effective roles.
 */
@FunctionalInterface
public interface RoleMapper {
    ImmutableSet<String> map(User user, TransportAddress caller);
}
