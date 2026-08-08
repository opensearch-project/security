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

package org.opensearch.security.dlic.rest.api.pagination;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;

/**
 * Pagination cursor for Security API collection GETs.
 *
 */
public final class PaginationCursor {

    static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String FIELD_CTYPE = "ctype";
    private static final String FIELD_SORT = "sort";
    private static final String FIELD_LAST_KEY = "last_key";

    /** The opaque Base64url string received from the client as {@code next_token}. */
    public final String token;

    /** The last entity name included on the previous page — the resume position. */
    public final String lastKey;

    private PaginationCursor(final String token, final String lastKey) {
        this.token = token;
        this.lastKey = lastKey;
    }

    /**
     * Encodes a new cursor capturing the current traversal position.
     *
     * @param ctype   configuration type of the current endpoint
     * @param sort    sort direction in use ({@code "asc"} or {@code "desc"})
     * @param lastKey last entity name returned on this page
     * @return a new {@link PaginationCursor}
     */
    public static PaginationCursor encode(final CType<?> ctype, final String sort, final String lastKey) {
        final ObjectNode node = MAPPER.createObjectNode();
        node.put(FIELD_CTYPE, ctype.toLCString());
        node.put(FIELD_SORT, sort);
        node.put(FIELD_LAST_KEY, lastKey);
        final String json = MAPPER.writeValueAsString(node);
        final String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        return new PaginationCursor(encoded, lastKey);
    }

    /**
     * Decodes and validates a cursor supplied by the client.
     *
     * @param encoded raw {@code next_token} value from the request
     * @param ctype   expected configuration type
     * @param sort    expected sort direction
     * @return a successful {@link ValidationResult} containing the decoded {@link PaginationCursor},
     *         or a {@code 400 Bad Request} error
     */
    public static ValidationResult<PaginationCursor> decode(final String encoded, final CType<?> ctype, final String sort) {
        try {
            final byte[] bytes = Base64.getUrlDecoder().decode(encoded);
            final JsonNode node = MAPPER.readTree(new String(bytes, StandardCharsets.UTF_8));

            if (!node.isObject()) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Invalid next_token: not a JSON object."));
            }
            if (!node.has(FIELD_CTYPE) || !node.has(FIELD_SORT) || !node.has(FIELD_LAST_KEY)) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Invalid next_token: missing required fields."));
            }

            final String tokenCtype = node.get(FIELD_CTYPE).asText();
            final String tokenSort = node.get(FIELD_SORT).asText();
            final String tokenLastKey = node.get(FIELD_LAST_KEY).asText();

            if (tokenCtype.isEmpty() || tokenSort.isEmpty() || tokenLastKey.isEmpty()) {
                return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Invalid next_token: missing required fields."));
            }
            if (!ctype.toLCString().equals(tokenCtype)) {
                return ValidationResult.error(
                    RestStatus.BAD_REQUEST,
                    badRequestMessage("Invalid next_token: token was issued for a different endpoint.")
                );
            }
            if (!sort.equals(tokenSort)) {
                return ValidationResult.error(
                    RestStatus.BAD_REQUEST,
                    badRequestMessage("Invalid next_token: sort direction does not match token.")
                );
            }
            return ValidationResult.success(new PaginationCursor(encoded, tokenLastKey));
        } catch (Exception e) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage("Invalid next_token: " + e.getMessage()));
        }
    }
}
