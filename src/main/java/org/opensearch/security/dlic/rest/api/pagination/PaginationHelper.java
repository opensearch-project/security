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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.api.SecurityConfiguration;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;

import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;

/**
 * Shared pagination utility for Security configuration collection GET endpoints.
 *
 * <p>The contract mirrors the OpenSearch {@code _list/*} APIs (see
 * <a href="https://github.com/opensearch-project/OpenSearch/pull/14641">OpenSearch#14641</a>) so callers
 * see a consistent surface across cluster and plugin configuration APIs:
 * <ul>
 *     <li>{@code size} — positive page size, capped at {@value #MAX_PAGE_SIZE}, defaulting to
 *         {@value #DEFAULT_PAGE_SIZE} when pagination is requested.</li>
 *     <li>{@code next_token} — opaque cursor returned by the preceding page; {@code null} on the final page.</li>
 *     <li>{@code sort} — {@code asc} or {@code desc}; sorts by configuration entity name; defaults to {@code asc}.</li>
 * </ul>
 *
 * <p>Pagination is opt-in per request: unless the caller sets one of {@code size},
 * {@code next_token}, or {@code sort}, the response retains its exact pre-existing shape. When any
 * pagination parameter is present, the response is wrapped as:
 * <pre>
 * {
 *   "next_token": null | "&lt;opaque&gt;",
 *   "&lt;ctype&gt;": { "&lt;name_a&gt;": {...}, "&lt;name_b&gt;": {...} }
 * }
 * </pre>
 *
 * <p>Cursors are bound to (cursor format version, {@link CType}, sort direction, last returned entity
 * name). Cursors decoded with any mismatched field, tampered content, or an invalid Base64/JSON
 * payload are rejected with HTTP 400. Because continuation is name-based (lexical), the entity
 * referenced by a cursor does not need to still exist — additions or deletions before the cursor do
 * not shift later pages.
 */
public final class PaginationHelper {

    public static final String PARAM_SIZE = "size";
    public static final String PARAM_NEXT_TOKEN = "next_token";
    public static final String PARAM_SORT = "sort";

    public static final String SORT_ASC = "asc";
    public static final String SORT_DESC = "desc";

    public static final int DEFAULT_PAGE_SIZE = 100;
    public static final int MAX_PAGE_SIZE = 1000;

    /** Current opaque-cursor payload format. Bump when the on-wire structure changes. */
    static final int CURSOR_VERSION = 1;

    private static final String CURSOR_FIELD_VERSION = "v";
    private static final String CURSOR_FIELD_CTYPE = "c";
    private static final String CURSOR_FIELD_SORT = "s";
    private static final String CURSOR_FIELD_LAST_NAME = "n";

    private static final String INVALID_CURSOR_MESSAGE = "Parameter [next_token] is invalid or has been tampered with.";
    private static final String CROSS_ENDPOINT_CURSOR_MESSAGE =
        "Parameter [next_token] was issued for a different endpoint. Restart pagination without [next_token].";
    private static final String CROSS_DIRECTION_CURSOR_MESSAGE =
        "Parameter [next_token] was issued for a different sort direction. Restart pagination without [next_token].";

    private PaginationHelper() {}

    /**
     * Returns {@code true} if the caller supplied any of {@link #PARAM_SIZE}, {@link #PARAM_NEXT_TOKEN},
     * or {@link #PARAM_SORT} — i.e. requested paginated response semantics.
     */
    public static boolean isRequested(final RestRequest request) {
        return request.hasParam(PARAM_SIZE) || request.hasParam(PARAM_NEXT_TOKEN) || request.hasParam(PARAM_SORT);
    }

    /**
     * Consumes the pagination query parameters from the request so that callers of
     * {@code BaseRestHandler} do not reject them as unrecognized. Intended to be invoked once from
     * {@code prepareRequest}, regardless of whether the endpoint opts into pagination.
     */
    public static void consumeParameters(final RestRequest request) {
        request.param(PARAM_SIZE);
        request.param(PARAM_NEXT_TOKEN);
        request.param(PARAM_SORT);
    }

    /**
     * Applies pagination to a Security configuration collection GET result if the caller requested
     * it. Returns a {@link ToXContent} suitable for {@code Responses.ok(channel, ToXContent)}:
     * <ul>
     *     <li>When no pagination parameters were provided, returns the configuration unchanged so
     *         non-paginated responses retain their exact existing shape.</li>
     *     <li>When pagination was requested on a collection GET, returns a wrapper that emits
     *         {@code {"next_token": ..., "<ctype>": {entries}}}.</li>
     *     <li>When pagination parameters were provided against a single-entity GET, returns
     *         {@link ValidationResult#error(RestStatus, ToXContent)} with HTTP 400.</li>
     *     <li>When any pagination parameter is invalid (bad size, unknown sort, malformed or
     *         cross-endpoint {@code next_token}), returns HTTP 400.</li>
     * </ul>
     */
    public static ValidationResult<ToXContent> apply(
        final RestRequest request,
        final CType<?> ctype,
        final SecurityConfiguration securityConfiguration
    ) throws IOException {
        final boolean requested = isRequested(request);
        final boolean singleEntity = securityConfiguration.maybeEntityName().isPresent();

        if (singleEntity) {
            if (requested) {
                return ValidationResult.error(
                    RestStatus.BAD_REQUEST,
                    badRequestMessage("Pagination parameters are not supported on single-entity GET requests.")
                );
            }
            return ValidationResult.success(securityConfiguration.configuration());
        }

        if (!requested) {
            return ValidationResult.success(securityConfiguration.configuration());
        }

        return parseAndValidate(request, ctype).map(
            params -> ValidationResult.<ToXContent>success(paginate(securityConfiguration.configuration(), params, ctype))
        );
    }

    static ValidationResult<PaginationParams> parseAndValidate(final RestRequest request, final CType<?> ctype) {
        try {
            // Sort
            final String rawSort = request.param(PARAM_SORT, SORT_ASC);
            if (!SORT_ASC.equals(rawSort) && !SORT_DESC.equals(rawSort)) {
                return ValidationResult.error(
                    RestStatus.BAD_REQUEST,
                    badRequestMessage("Parameter [sort] must be either [asc] or [desc].")
                );
            }

            // Size
            final String rawSize = request.param(PARAM_SIZE);
            int size = DEFAULT_PAGE_SIZE;
            if (rawSize != null) {
                try {
                    size = Integer.parseInt(rawSize);
                } catch (NumberFormatException e) {
                    return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        badRequestMessage("Parameter [size] must be a positive integer between 1 and " + MAX_PAGE_SIZE + ".")
                    );
                }
                if (size < 1 || size > MAX_PAGE_SIZE) {
                    return ValidationResult.error(
                        RestStatus.BAD_REQUEST,
                        badRequestMessage("Parameter [size] must be a positive integer between 1 and " + MAX_PAGE_SIZE + ".")
                    );
                }
            }
            final int resolvedSize = size;

            // next_token (bound to ctype + sort direction; issuer-format-versioned)
            final String rawToken = request.param(PARAM_NEXT_TOKEN);
            if (rawToken == null || rawToken.isEmpty()) {
                return ValidationResult.success(new PaginationParams(resolvedSize, rawSort, null));
            }
            return decodeCursor(rawToken, ctype, rawSort).map(
                lastName -> ValidationResult.success(new PaginationParams(resolvedSize, rawSort, lastName))
            );
        } catch (IOException e) {
            // ValidationResult#map declares IOException; parseAndValidate itself does no IO, so this is unreachable
            // in practice — surface it as a 400 rather than a 500 to keep the contract predictable.
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(INVALID_CURSOR_MESSAGE));
        }
    }

    private static ValidationResult<String> decodeCursor(final String rawToken, final CType<?> expectedCtype, final String expectedSort) {
        final byte[] decoded;
        try {
            // URL-safe Base64 without padding, matching {@link #encodeCursor}. Standard Base64
            // is intentionally NOT accepted so cursors we hand out are round-trip safe through any
            // HTTP client (including those that form-encode query strings and would corrupt '+').
            decoded = Base64.getUrlDecoder().decode(rawToken);
        } catch (IllegalArgumentException e) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(INVALID_CURSOR_MESSAGE));
        }
        final String json = new String(decoded, StandardCharsets.UTF_8);
        final JsonNode node;
        try {
            node = DefaultObjectMapper.readTree(json);
        } catch (IOException e) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(INVALID_CURSOR_MESSAGE));
        }
        if (node == null || !node.isObject()) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(INVALID_CURSOR_MESSAGE));
        }

        final JsonNode versionNode = node.get(CURSOR_FIELD_VERSION);
        final JsonNode ctypeNode = node.get(CURSOR_FIELD_CTYPE);
        final JsonNode sortNode = node.get(CURSOR_FIELD_SORT);
        final JsonNode nameNode = node.get(CURSOR_FIELD_LAST_NAME);
        if (versionNode == null
            || !versionNode.isInt()
            || versionNode.asInt() != CURSOR_VERSION
            || ctypeNode == null
            || !ctypeNode.isString()
            || sortNode == null
            || !sortNode.isString()
            || nameNode == null
            || !nameNode.isString()) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(INVALID_CURSOR_MESSAGE));
        }

        if (!expectedCtype.toLCString().equals(ctypeNode.asString())) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(CROSS_ENDPOINT_CURSOR_MESSAGE));
        }
        if (!expectedSort.equals(sortNode.asString())) {
            return ValidationResult.error(RestStatus.BAD_REQUEST, badRequestMessage(CROSS_DIRECTION_CURSOR_MESSAGE));
        }

        return ValidationResult.success(nameNode.asString());
    }

    static String encodeCursor(final CType<?> ctype, final String sort, final String lastName) {
        Objects.requireNonNull(lastName, "lastName");
        final Map<String, Object> payload = new TreeMap<>();
        payload.put(CURSOR_FIELD_VERSION, CURSOR_VERSION);
        payload.put(CURSOR_FIELD_CTYPE, ctype.toLCString());
        payload.put(CURSOR_FIELD_SORT, sort);
        payload.put(CURSOR_FIELD_LAST_NAME, lastName);
        final String json = DefaultObjectMapper.writeValueAsString(payload, false);
        // URL-safe Base64 without padding so the emitted token can be dropped straight into a
        // {@code next_token=} query parameter by any HTTP client without further encoding.
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    static PaginatedConfigurationResponse paginate(
        final SecurityDynamicConfiguration<?> configuration,
        final PaginationParams params,
        final CType<?> ctype
    ) {
        final Map<String, ?> entries = configuration.getCEntries();
        final List<String> sortedNames = new ArrayList<>(entries.keySet());
        final Comparator<String> comparator = SORT_ASC.equals(params.sort) ? Comparator.naturalOrder() : Comparator.reverseOrder();
        Collections.sort(sortedNames, comparator);

        // Lexical continuation from the cursor's last name: consume names strictly beyond it.
        int startIdx = 0;
        if (params.lastName != null) {
            while (startIdx < sortedNames.size() && comparator.compare(sortedNames.get(startIdx), params.lastName) <= 0) {
                startIdx++;
            }
        }

        final int endIdx = Math.min(startIdx + params.size, sortedNames.size());
        final List<String> pageNames = sortedNames.subList(startIdx, endIdx);

        final String nextToken;
        if (endIdx < sortedNames.size() && !pageNames.isEmpty()) {
            nextToken = encodeCursor(ctype, params.sort, pageNames.get(pageNames.size() - 1));
        } else {
            nextToken = null;
        }

        return new PaginatedConfigurationResponse(pageNames, configuration, ctype, nextToken);
    }

    /**
     * Parsed and validated pagination parameters.
     */
    public static final class PaginationParams {

        final int size;
        final String sort;
        final String lastName;

        PaginationParams(final int size, final String sort, final String lastName) {
            this.size = size;
            this.sort = sort;
            this.lastName = lastName;
        }

        public int size() {
            return size;
        }

        public String sort() {
            return sort;
        }

        public String lastName() {
            return lastName;
        }
    }

    /**
     * {@link ToXContent} view that renders the paginated response wrapper:
     * <pre>
     * {
     *   "next_token": null | "&lt;opaque&gt;",
     *   "&lt;ctype&gt;": {"&lt;name&gt;": {...}, ...}
     * }
     * </pre>
     * Ordering of page entries matches the requested sort direction.
     */
    public static final class PaginatedConfigurationResponse implements ToXContent {

        private static final TypeReference<HashMap<String, Object>> TYPE_REF_MSO = new TypeReference<>() {
        };

        private final List<String> pageNames;
        private final SecurityDynamicConfiguration<?> configuration;
        private final CType<?> ctype;
        private final String nextToken;

        PaginatedConfigurationResponse(
            final List<String> pageNames,
            final SecurityDynamicConfiguration<?> configuration,
            final CType<?> ctype,
            final String nextToken
        ) {
            this.pageNames = pageNames;
            this.configuration = configuration;
            this.ctype = ctype;
            this.nextToken = nextToken;
        }

        @Override
        public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
            // Serialize the full configuration to a Map exactly as SecurityDynamicConfiguration does,
            // so page entries render identically to the non-paginated response shape. We then keep
            // only the entries in `pageNames` (in the ordering requested by the caller).
            final boolean omitDefaults = params != null && params.paramAsBoolean("omit_defaults", false);
            final Map<String, Object> full = DefaultObjectMapper.readValue(
                DefaultObjectMapper.writeValueAsString(configuration, omitDefaults),
                TYPE_REF_MSO
            );

            builder.startObject();
            if (nextToken == null) {
                builder.nullField(PARAM_NEXT_TOKEN);
            } else {
                builder.field(PARAM_NEXT_TOKEN, nextToken);
            }
            builder.startObject(ctype.toLCString());
            for (final String name : pageNames) {
                final Object entry = full.get(name);
                if (entry == null) {
                    continue;
                }
                builder.field(name, entry);
            }
            builder.endObject();
            builder.endObject();
            return builder;
        }

        public String nextToken() {
            return nextToken;
        }

        public List<String> pageNames() {
            return Collections.unmodifiableList(pageNames);
        }
    }
}
