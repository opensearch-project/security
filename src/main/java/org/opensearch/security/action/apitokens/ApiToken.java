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

package org.opensearch.security.action.apitokens;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

public class ApiToken implements ToXContent {
    private String description;
    private String jti;

    private Instant creationTime;
    private List<String> clusterPermissions;
    private List<RoleV7.Index> indexPermissions;

    public ApiToken(String description, String jti, List<String> clusterPermissions, List<RoleV7.Index> indexPermissions) {
        this.creationTime = Instant.now();
        this.description = description;
        this.jti = jti;
        this.clusterPermissions = clusterPermissions;
        this.indexPermissions = indexPermissions;

    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(Instant creationTime) {
        this.creationTime = creationTime;
    }

    public List<String> getClusterPermissions() {
        return clusterPermissions;
    }

    public void setClusterPermissions(List<String> clusterPermissions) {
        this.clusterPermissions = clusterPermissions;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, ToXContent.Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("description", description);
        xContentBuilder.field("jti", jti);
        xContentBuilder.field("cluster_permissions", clusterPermissions);
        xContentBuilder.field("index_permissions", indexPermissions);
        xContentBuilder.field("creation_time", creationTime.toEpochMilli());
        xContentBuilder.endObject();
        return xContentBuilder;
    }

    public List<RoleV7.Index> getIndexPermissions() {
        return indexPermissions;
    }

    public void setIndexPermissions(List<RoleV7.Index> indexPermissions) {
        this.indexPermissions = indexPermissions;
    }
}
