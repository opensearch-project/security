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

public class ApiToken implements ToXContent {
    private String name;
    private final String jti;
    private final Instant creationTime;
    private List<String> clusterPermissions;
    private List<IndexPermission> indexPermissions;

    public ApiToken(String name, String jti, List<String> clusterPermissions, List<IndexPermission> indexPermissions) {
        this.creationTime = Instant.now();
        this.name = name;
        this.jti = jti;
        this.clusterPermissions = clusterPermissions;
        this.indexPermissions = indexPermissions;

    }

    public ApiToken(
        String description,
        String jti,
        List<String> clusterPermissions,
        List<IndexPermission> indexPermissions,
        Instant creationTime
    ) {
        this.name = description;
        this.jti = jti;
        this.clusterPermissions = clusterPermissions;
        this.indexPermissions = indexPermissions;
        this.creationTime = creationTime;

    }

    public static class IndexPermission implements ToXContent {
        private final List<String> indexPatterns;
        private final List<String> allowedActions;

        public IndexPermission(List<String> indexPatterns, List<String> allowedActions) {
            this.indexPatterns = indexPatterns;
            this.allowedActions = allowedActions;
        }

        public List<String> getAllowedActions() {
            return allowedActions;
        }

        public List<String> getIndexPatterns() {
            return indexPatterns;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.array("index_patterns", indexPatterns.toArray(new String[0]));
            builder.array("allowed_actions", allowedActions.toArray(new String[0]));
            builder.endObject();
            return builder;
        }
    }

    public static ApiToken fromXContent(XContentParser parser) throws IOException {
        String description = null;
        String jti = null;
        List<String> clusterPermissions = new ArrayList<>();
        List<IndexPermission> indexPermissions = new ArrayList<>();
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

    private static IndexPermission parseIndexPermission(XContentParser parser) throws IOException {
        List<String> indexPatterns = new ArrayList<>();
        List<String> allowedActions = new ArrayList<>();

        String currentFieldName = null;
        XContentParser.Token token;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
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

                }
            }
        }

        if (indexPatterns.isEmpty()) {
            throw new IllegalArgumentException("index_patterns is required for index permission");
        }

        return new IndexPermission(indexPatterns, allowedActions);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getJti() {
        return jti;
    }

    public Instant getCreationTime() {
        return creationTime;
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
        xContentBuilder.field("name", name);
        xContentBuilder.field("jti", jti);
        xContentBuilder.field("cluster_permissions", clusterPermissions);
        xContentBuilder.field("index_permissions", indexPermissions);
        xContentBuilder.field("creation_time", creationTime.toEpochMilli());
        xContentBuilder.endObject();
        return xContentBuilder;
    }

    public List<IndexPermission> getIndexPermissions() {
        return indexPermissions;
    }

    public void setIndexPermissions(List<IndexPermission> indexPermissions) {
        this.indexPermissions = indexPermissions;
    }
}
