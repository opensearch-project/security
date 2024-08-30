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

package org.opensearch.security.resources;

import java.util.List;
import java.util.Map;

import org.opensearch.accesscontrol.resources.EntityType;
import org.opensearch.accesscontrol.resources.ResourceSharing;

public class ResourceAccessEvaluator {

    public Map<String, List<String>> listAccessibleResources() {
        return Map.of();
    }

    public List<String> listAccessibleResourcesForPlugin(String s) {
        return List.of();
    }

    public boolean hasPermission(String resourceId, String systemIndexName) {
        return false;
    }

    public ResourceSharing shareWith(String resourceId, String systemIndexName, Map<EntityType, List<String>> map) {
        return null;
    }

    public ResourceSharing revokeAccess(String resourceId, String systemIndexName, Map<EntityType, List<String>> map) {
        return null;
    }

    public boolean deleteResourceSharingRecord(String resourceId, String systemIndexName) {
        return false;
    }

    public boolean deleteAllResourceSharingRecordsFor(String entity) {
        return false;
    }

}
