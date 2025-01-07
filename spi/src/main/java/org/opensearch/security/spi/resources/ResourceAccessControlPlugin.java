/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

/**
 * This plugin allows to control access to resources. It is used by the ResourcePlugins to check whether a user has access to a resource defined by that plugin.
 * It also defines java APIs to list, share or revoke resources with other users.
 * User information will be fetched from the ThreadContext.
 *
 * @opensearch.experimental
 */
public interface ResourceAccessControlPlugin {

    boolean hasPermission(String resourceId, String resourceIndex, ResourceAccessScope<? extends Enum<?>> scope);
}
