/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.action.apitokens;

import java.util.List;

public class Permissions {
    private List<String> clusterPerm;
    private List<ApiToken.IndexPermission> indexPermission;

    // Constructor
    public Permissions(List<String> clusterPerm, List<ApiToken.IndexPermission> indexPermission) {
        this.clusterPerm = clusterPerm;
        this.indexPermission = indexPermission;
    }

    // Getters and setters
    public List<String> getClusterPerm() {
        return clusterPerm;
    }

    public void setClusterPerm(List<String> clusterPerm) {
        this.clusterPerm = clusterPerm;
    }

    public List<ApiToken.IndexPermission> getIndexPermission() {
        return indexPermission;
    }

    public void setIndexPermission(List<ApiToken.IndexPermission> indexPermission) {
        this.indexPermission = indexPermission;
    }

}
