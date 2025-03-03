/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.client.resources;

import java.util.Map;
import java.util.Set;

import org.opensearch.core.action.ActionListener;
import org.opensearch.security.spi.resources.Resource;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;

public interface ResourceSharingClient {

    void verifyResourceAccess(String resourceId, String resourceIndex, String scope, ActionListener<Boolean> listener);

    void shareResource(String resourceId, String resourceIndex, Map<String, Object> shareWith, ActionListener<ResourceSharing> listener);

    void revokeResourceAccess(
        String resourceId,
        String resourceIndex,
        Map<String, Object> entitiesToRevoke,
        Set<String> scopes,
        ActionListener<ResourceSharing> listener
    );

    void listAccessibleResourcesForCurrentUser(String resourceIndex, ActionListener<Set<? extends Resource>> listener);
}
