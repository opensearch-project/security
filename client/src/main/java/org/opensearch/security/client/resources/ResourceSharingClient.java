/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.client.resources;

import org.opensearch.core.action.ActionListener;

import java.util.List;

public interface ResourceSharingClient {

    void verifyResourceAccess(String resourceId, String resourceIndex, String scope, ActionListener<Boolean> listener);

    void grantResourceAccess(
        String resourceId,
        String resourceIndex,
        String userOrRole,
        String accessLevel,
        ActionListener<Boolean> listener
    );

    void revokeResourceAccess(String resourceId, String resourceIndex, String userOrRole, ActionListener<Boolean> listener);

    void listAccessibleResources(String userOrRole, ActionListener<List<String>> listener);
}
