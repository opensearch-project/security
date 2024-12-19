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

import com.fasterxml.jackson.annotation.JsonIgnore;

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonElement;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParseException;
import com.nimbusds.jose.shaded.gson.JsonParser;

public class ApiToken implements ToXContent {
    public static final String NAME_FIELD = "name";
    public static final String JTI_FIELD = "jti";
    public static final String CREATION_TIME_FIELD = "creation_time";
    public static final String CLUSTER_PERMISSIONS_FIELD = "cluster_permissions";
    public static final String INDEX_PERMISSIONS_FIELD = "index_permissions";
    public static final String INDEX_PATTERN_FIELD = "index_pattern";
    public static final String ALLOWED_ACTIONS_FIELD = "allowed_actions";
    public static final String EXPIRATION_FIELD = "expiration";

    private final String name;
    private String jti;
    private final Instant creationTime;
    private final List<String> clusterPermissions;
    private final List<IndexPermission> indexPermissions;
    private final long expiration;

    public ApiToken(String name, String jti, List<String> clusterPermissions, List<IndexPermission> indexPermissions, Long expiration) {
        this.creationTime = Instant.now();
        this.jti = jti;
        this.name = name;
        this.clusterPermissions = clusterPermissions;
        this.indexPermissions = indexPermissions;
        this.expiration = expiration;
    }

    public ApiToken(
        String name,
        String jti,
        List<String> clusterPermissions,
        List<IndexPermission> indexPermissions,
        Instant creationTime,
        Long expiration
    ) {
        this.name = name;
        this.jti = jti;
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

        // TODO: look into integrating with default object mapper
        @Override
        public String toString() {
            JsonObject json = new JsonObject();
            JsonArray patternsArray = new JsonArray();
            JsonArray actionsArray = new JsonArray();

            for (String pattern : indexPatterns) {
                patternsArray.add(pattern);
            }
            for (String action : allowedActions) {
                actionsArray.add(action);
            }

            json.add(INDEX_PATTERN_FIELD, patternsArray);
            json.add(ALLOWED_ACTIONS_FIELD, actionsArray);

            return json.toString();
        }

        public static IndexPermission fromString(String str) {
            try {
                JsonObject json = JsonParser.parseString(str).getAsJsonObject();
                return new IndexPermission(
                    json.get(INDEX_PATTERN_FIELD).getAsJsonArray().asList().stream().map(JsonElement::getAsString).toList(),
                    json.get(ALLOWED_ACTIONS_FIELD).getAsJsonArray().asList().stream().map(JsonElement::getAsString).toList()
                );
            } catch (JsonParseException e) {
                throw new IllegalArgumentException("Invalid IndexPermission format", e);
            }
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
        String jti = null;
        List<String> clusterPermissions = new ArrayList<>();
        List<IndexPermission> indexPermissions = new ArrayList<>();
        Instant creationTime = null;
        long expiration = Long.MAX_VALUE;

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
                    case JTI_FIELD:
                        jti = parser.text();
                        break;
                    case CREATION_TIME_FIELD:
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

        return new ApiToken(name, jti, clusterPermissions, indexPermissions, creationTime, expiration);
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

    @JsonIgnore
    public String getJti() {
        return jti;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public List<String> getClusterPermissions() {
        return clusterPermissions;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, ToXContent.Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field(NAME_FIELD, name);
        xContentBuilder.field(JTI_FIELD, jti);
        xContentBuilder.field(CLUSTER_PERMISSIONS_FIELD, clusterPermissions);
        xContentBuilder.field(INDEX_PERMISSIONS_FIELD, indexPermissions);
        xContentBuilder.field(CREATION_TIME_FIELD, creationTime.toEpochMilli());
        xContentBuilder.endObject();
        return xContentBuilder;
    }

    public List<IndexPermission> getIndexPermissions() {
        return indexPermissions;
    }
}
