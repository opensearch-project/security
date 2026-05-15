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

import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.opensearch.core.xcontent.ConstructingObjectParser.constructorArg;
import static org.opensearch.core.xcontent.ConstructingObjectParser.optionalConstructorArg;

public class ApiToken implements ToXContent {
    public static final String NAME_FIELD = "name";
    public static final String ID_FIELD = "id";
    public static final String ISSUED_AT_FIELD = "iat";
    public static final String CLUSTER_PERMISSIONS_FIELD = "cluster_permissions";
    public static final String INDEX_PERMISSIONS_FIELD = "index_permissions";
    public static final String INDEX_PATTERN_FIELD = "index_pattern";
    public static final String ALLOWED_ACTIONS_FIELD = "allowed_actions";
    public static final String DURATION_SECONDS_FIELD = "duration_seconds";
    public static final String EXPIRES_AT_FIELD = "expires_at";
    public static final String TOKEN_HASH_FIELD = "token_hash";
    public static final String REVOKED_AT_FIELD = "revoked_at";
    public static final String CREATED_BY_FIELD = "created_by";

    @SuppressWarnings("unchecked")
    private static final ConstructingObjectParser<ApiToken, Void> PARSER = new ConstructingObjectParser<>(
        "api_token",
        false,
        args -> new ApiToken(
            (String) args[0],
            (String) args[1],
            args[2] != null ? (List<String>) args[2] : List.of(),
            args[3] != null ? (List<IndexPermission>) args[3] : List.<IndexPermission>of(),
            args[4] != null ? Instant.ofEpochMilli((Long) args[4]) : null,
            args[5] != null ? (Long) args[5] : 0L,
            args[6] != null ? Instant.ofEpochMilli((Long) args[6]) : null,
            (String) args[7]
        )
    );

    static {
        PARSER.declareString(constructorArg(), new ParseField(NAME_FIELD));
        PARSER.declareString(constructorArg(), new ParseField(TOKEN_HASH_FIELD));
        PARSER.declareStringArray(optionalConstructorArg(), new ParseField(CLUSTER_PERMISSIONS_FIELD));
        PARSER.declareObjectArray(
            optionalConstructorArg(),
            (p, c) -> IndexPermission.fromXContent(p),
            new ParseField(INDEX_PERMISSIONS_FIELD)
        );
        PARSER.declareLong(optionalConstructorArg(), new ParseField(ISSUED_AT_FIELD));
        PARSER.declareLong(optionalConstructorArg(), new ParseField(EXPIRES_AT_FIELD));
        PARSER.declareLong(optionalConstructorArg(), new ParseField(REVOKED_AT_FIELD));
        PARSER.declareString(optionalConstructorArg(), new ParseField(CREATED_BY_FIELD));
    }

    private final String name;
    private final String tokenHash;
    private String id;
    private final Instant creationTime;
    private final List<String> clusterPermissions;
    private final List<IndexPermission> indexPermissions;
    private final long expiration;
    private final Instant revokedAt;
    private final String createdBy;

    public ApiToken(
        String name,
        String tokenHash,
        List<String> clusterPermissions,
        List<IndexPermission> indexPermissions,
        Instant creationTime,
        Long expiration
    ) {
        this(name, tokenHash, clusterPermissions, indexPermissions, creationTime, expiration, null, null);
    }

    public ApiToken(
        String name,
        String tokenHash,
        List<String> clusterPermissions,
        List<IndexPermission> indexPermissions,
        Instant creationTime,
        Long expiration,
        Instant revokedAt,
        String createdBy
    ) {
        this.name = name;
        this.tokenHash = tokenHash;
        this.clusterPermissions = clusterPermissions;
        this.indexPermissions = indexPermissions;
        this.creationTime = creationTime;
        this.expiration = expiration;
        this.revokedAt = revokedAt;
        this.createdBy = createdBy;
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

        @SuppressWarnings("unchecked")
        private static final ConstructingObjectParser<IndexPermission, Void> PARSER = new ConstructingObjectParser<>(
            "index_permission",
            false,
            args -> new IndexPermission(
                args[0] != null ? (List<String>) args[0] : List.of(),
                args[1] != null ? (List<String>) args[1] : List.of()
            )
        );

        static {
            PARSER.declareStringArray(optionalConstructorArg(), new ParseField(INDEX_PATTERN_FIELD));
            PARSER.declareStringArray(optionalConstructorArg(), new ParseField(ALLOWED_ACTIONS_FIELD));
        }

        public static IndexPermission fromXContent(XContentParser parser) throws IOException {
            return PARSER.parse(parser, null);
        }
    }

    public static ApiToken fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTokenHash() {
        return tokenHash;
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
        xContentBuilder.field(TOKEN_HASH_FIELD, tokenHash);
        xContentBuilder.field(CLUSTER_PERMISSIONS_FIELD, clusterPermissions);
        xContentBuilder.field(INDEX_PERMISSIONS_FIELD, indexPermissions);
        xContentBuilder.field(ISSUED_AT_FIELD, creationTime.toEpochMilli());
        xContentBuilder.field(EXPIRES_AT_FIELD, expiration);
        if (revokedAt != null) {
            xContentBuilder.field(REVOKED_AT_FIELD, revokedAt.toEpochMilli());
        }
        if (createdBy != null) {
            xContentBuilder.field(CREATED_BY_FIELD, createdBy);
        }
        xContentBuilder.endObject();
        return xContentBuilder;
    }

    public List<IndexPermission> getIndexPermissions() {
        return indexPermissions;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public static class CreateRequest {
        @SuppressWarnings("unchecked")
        private static final ConstructingObjectParser<CreateRequest, Void> PARSER = new ConstructingObjectParser<>(
            "create_api_token_request",
            false,
            args -> new CreateRequest(
                (String) args[0],
                args[1] != null ? (List<String>) args[1] : List.of(),
                args[2] != null ? (List<IndexPermission>) args[2] : List.<IndexPermission>of(),
                args[3] != null ? (Long) args[3] : 0L
            )
        );

        static {
            PARSER.declareString(constructorArg(), new ParseField(NAME_FIELD));
            PARSER.declareStringArray(optionalConstructorArg(), new ParseField(CLUSTER_PERMISSIONS_FIELD));
            PARSER.declareObjectArray(
                optionalConstructorArg(),
                (p, c) -> IndexPermission.fromXContent(p),
                new ParseField(INDEX_PERMISSIONS_FIELD)
            );
            PARSER.declareLong(optionalConstructorArg(), new ParseField(DURATION_SECONDS_FIELD));
        }

        private final String name;
        private final List<String> clusterPermissions;
        private final List<IndexPermission> indexPermissions;
        private final long durationSeconds;

        public CreateRequest(String name, List<String> clusterPermissions, List<IndexPermission> indexPermissions, long durationSeconds) {
            this.name = name;
            this.clusterPermissions = clusterPermissions;
            this.indexPermissions = indexPermissions;
            this.durationSeconds = durationSeconds;
        }

        public static CreateRequest fromXContent(XContentParser parser) throws IOException {
            return PARSER.parse(parser, null);
        }

        public String getName() {
            return name;
        }

        public List<String> getClusterPermissions() {
            return clusterPermissions;
        }

        public List<IndexPermission> getIndexPermissions() {
            return indexPermissions;
        }

        public long getDurationSeconds() {
            return durationSeconds;
        }
    }

    public static class DeleteRequest {
        private static final ConstructingObjectParser<DeleteRequest, Void> PARSER = new ConstructingObjectParser<>(
            "delete_api_token_request",
            false,
            args -> new DeleteRequest((String) args[0])
        );

        static {
            PARSER.declareString(constructorArg(), new ParseField(ID_FIELD));
        }

        private final String id;

        public DeleteRequest(String id) {
            this.id = id;
        }

        public static DeleteRequest fromXContent(XContentParser parser) throws IOException {
            return PARSER.parse(parser, null);
        }

        public String getId() {
            return id;
        }
    }
}
