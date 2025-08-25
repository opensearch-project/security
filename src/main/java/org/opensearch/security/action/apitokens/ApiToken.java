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
import java.util.Set;

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

public class ApiToken implements ToXContent {
    public static final String NAME_FIELD = "name";
    public static final String ISSUED_AT_FIELD = "iat";
    public static final String CLUSTER_PERMISSIONS_FIELD = "cluster_permissions";
    public static final String INDEX_PERMISSIONS_FIELD = "index_permissions";
    public static final String INDEX_PATTERN_FIELD = "index_pattern";
    public static final String ALLOWED_ACTIONS_FIELD = "allowed_actions";
    public static final String EXPIRATION_FIELD = "expiration";
    public static final Set<String> ALLOWED_FIELDS = Set.of(
        NAME_FIELD,
        EXPIRATION_FIELD,
        CLUSTER_PERMISSIONS_FIELD,
        INDEX_PERMISSIONS_FIELD
    );

    private final String name;
    private final Instant creationTime;
    private final List<String> clusterPermissions;
    private final List<IndexPermission> indexPermissions;
    private final long expiration;

    public ApiToken(
        String name,
        List<String> clusterPermissions,
        List<IndexPermission> indexPermissions,
        Instant creationTime,
        Long expiration
    ) {
        this.name = name;
        this.clusterPermissions = clusterPermissions;
        this.indexPermissions = indexPermissions;
        this.creationTime = creationTime;
        this.expiration = expiration;
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
            builder.array(INDEX_PATTERN_FIELD, indexPatterns.toArray(new String[0]));
            builder.array(ALLOWED_ACTIONS_FIELD, allowedActions.toArray(new String[0]));
            builder.endObject();
            return builder;
        }

        public static IndexPermission fromXContent(XContentParser parser) throws IOException {
            List<String> indexPatterns = new ArrayList<>();
            List<String> allowedActions = new ArrayList<>();

            XContentParser.Token token;
            String currentFieldName = null;

            while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                if (token == XContentParser.Token.FIELD_NAME) {
                    currentFieldName = parser.currentName();
                } else if (token == XContentParser.Token.START_ARRAY) {
                    switch (currentFieldName) {
                        case INDEX_PATTERN_FIELD:
                            while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                                indexPatterns.add(parser.text());
                            }
                            break;
                        case ALLOWED_ACTIONS_FIELD:
                            while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                                allowedActions.add(parser.text());
                            }
                            break;
                    }
                }
            }

            return new IndexPermission(indexPatterns, allowedActions);
        }

    }

    /**
     * Class represents an API token.
     * Expected class structure
     * {
     *   name: "token_name",
     *   jti: "encrypted_token",
     *   creation_time: 1234567890,
     *   cluster_permissions: ["cluster_permission1", "cluster_permission2"],
     *   index_permissions: [
     *     {
     *       index_pattern: ["index_pattern1", "index_pattern2"],
     *       allowed_actions: ["allowed_action1", "allowed_action2"]
     *     }
     *   ],
     *   expiration: 1234567890
     * }
     */
    public static ApiToken fromXContent(XContentParser parser) throws IOException {
        String name = null;
        List<String> clusterPermissions = new ArrayList<>();
        List<IndexPermission> indexPermissions = new ArrayList<>();
        Instant creationTime = null;
        long expiration = 0;

        XContentParser.Token token;
        String currentFieldName = null;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token.isValue()) {
                switch (currentFieldName) {
                    case NAME_FIELD:
                        name = parser.text();
                        break;
                    case ISSUED_AT_FIELD:
                        creationTime = Instant.ofEpochMilli(parser.longValue());
                        break;
                    case EXPIRATION_FIELD:
                        expiration = parser.longValue();
                        break;
                }
            } else if (token == XContentParser.Token.START_ARRAY) {
                switch (currentFieldName) {
                    case CLUSTER_PERMISSIONS_FIELD:
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            clusterPermissions.add(parser.text());
                        }
                        break;
                    case INDEX_PERMISSIONS_FIELD:
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                                indexPermissions.add(parseIndexPermission(parser));
                            }
                        }
                        break;
                }
            }
        }

        return new ApiToken(name, clusterPermissions, indexPermissions, creationTime, expiration);
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
                    case INDEX_PATTERN_FIELD:
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            indexPatterns.add(parser.text());
                        }
                        break;
                    case ALLOWED_ACTIONS_FIELD:
                        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                            allowedActions.add(parser.text());
                        }
                        break;
                }
            }
        }
        return new IndexPermission(indexPatterns, allowedActions);
    }

    public String getName() {
        return name;
    }

    public Long getExpiration() {
        return expiration;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public List<String> getClusterPermissions() {
        return clusterPermissions;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field(NAME_FIELD, name);
        xContentBuilder.field(CLUSTER_PERMISSIONS_FIELD, clusterPermissions);
        xContentBuilder.field(INDEX_PERMISSIONS_FIELD, indexPermissions);
        xContentBuilder.field(ISSUED_AT_FIELD, creationTime.toEpochMilli());
        xContentBuilder.endObject();
        return xContentBuilder;
    }

    public List<IndexPermission> getIndexPermissions() {
        return indexPermissions;
    }
}
