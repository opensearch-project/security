/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources.fallback;

import org.opensearch.security.spi.resources.ResourceAccessControlPlugin;
import org.opensearch.security.spi.resources.ResourceAccessScope;

/**
 * A default plugin for resource access control
 */
public class DefaultResourceAccessControlPlugin implements ResourceAccessControlPlugin {
    /**
     * @param resourceId    the resource on which access is to be checked
     * @param resourceIndex where the resource exists
     * @param scope         the scope being requested
     * @return true always since this is a passthrough implementation
     */
    @Override
    public boolean hasPermission(String resourceId, String resourceIndex, ResourceAccessScope<? extends Enum<?>> scope) {
        return true;
    }
}
