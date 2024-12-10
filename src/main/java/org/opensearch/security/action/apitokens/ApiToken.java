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
import java.util.ArrayList;
import java.util.List;

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
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

    public ApiToken(
        String description,
        String jti,
        List<String> clusterPermissions,
        List<RoleV7.Index> indexPermissions,
        Instant creationTime
    ) {
        this.description = description;
        this.jti = jti;
        this.clusterPermissions = clusterPermissions;
        this.indexPermissions = indexPermissions;
        this.creationTime = creationTime;

    }

    public static ApiToken fromXContent(XContentParser parser) throws IOException {
        String description = null;
        String jti = null;
        List<String> clusterPermissions = new ArrayList<>();
        List<RoleV7.Index> indexPermissions = new ArrayList<>();
        Instant creationTime = null;

        XContentParser.Token token;
        String currentFieldName = null;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token.isValue()) {
                switch (currentFieldName) {
                    case "description":
                        description = parser.text();
                        break;
                    case "jti":
                        jti = parser.text();
                        break;
                    case "creation_time":
                        creationTime = Instant.ofEpochMilli(parser.longValue());
                        break;
                }
            } else if (token == XContentParser.Token.START_ARRAY) {
                switch (currentFieldName) {
                    case "cluster_permissions":
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            clusterPermissions.add(parser.text());
                        }
                        break;
                    case "index_permissions":
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                                indexPermissions.add(parseIndexPermission(parser));
                            }
                        }
                        break;
                }
            }
        }

        // Validate required fields
        if (description == null) {
            throw new IllegalArgumentException("description is required");
        }
        if (jti == null) {
            throw new IllegalArgumentException("jti is required");
        }
        if (creationTime == null) {
            throw new IllegalArgumentException("creation_time is required");
        }

        return new ApiToken(description, jti, clusterPermissions, indexPermissions, creationTime);
    }

    private static RoleV7.Index parseIndexPermission(XContentParser parser) throws IOException {
        List<String> indexPatterns = new ArrayList<>();
        List<String> allowedActions = new ArrayList<>();
        String dls = "";
        List<String> fls = new ArrayList<>();
        List<String> maskedFields = new ArrayList<>();

        String currentFieldName = null;
        XContentParser.Token token;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token.isValue()) {
                if ("dls".equals(currentFieldName)) {
                    dls = parser.text();
                }
            } else if (token == XContentParser.Token.START_ARRAY) {
                switch (currentFieldName) {
                    case "index_patterns":
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            indexPatterns.add(parser.text());
                        }
                        break;
                    case "allowed_actions":
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            allowedActions.add(parser.text());
                        }
                        break;
                    case "fls":
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            fls.add(parser.text());
                        }
                        break;
                    case "masked_fields":
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            maskedFields.add(parser.text());
                        }
                        break;
                }
            }
        }

        if (indexPatterns.isEmpty()) {
            throw new IllegalArgumentException("index_patterns is required for index permission");
        }

        return new RoleV7.Index(indexPatterns, allowedActions, dls, fls, maskedFields);
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
