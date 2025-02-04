/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.action.apitokens;

import java.util.Collections;
import java.util.List;

public class Permissions {
    private final List<String> clusterPerm;
    private final List<ApiToken.IndexPermission> indexPermission;

    public Permissions(List<String> clusterPerm, List<ApiToken.IndexPermission> indexPermission) {
        this.clusterPerm = clusterPerm;
        this.indexPermission = indexPermission;
    }

    public Permissions() {
        this.clusterPerm = Collections.emptyList();
        this.indexPermission = Collections.emptyList();
    }

    public List<String> getClusterPerm() {
        return clusterPerm;
    }

    public List<ApiToken.IndexPermission> getIndexPermission() {
        return indexPermission;
    }
}
