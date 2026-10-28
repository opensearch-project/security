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
import java.util.Map;

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.DefaultObjectMapper;

/**
 * A single page of a paginated collection response.
 *
 * @param <T> the configuration entry type
 */
public final class PaginationResult<T> implements ToXContent {

    private static final String FIELD_NEXT_TOKEN = PaginationRequestParser.RESPONSE_NEXT_TOKEN_KEY;
    public final String resourceKey;
    public final Map<String, T> entries;
    public final String nextToken;

    private PaginationResult(final String resourceKey, final Map<String, T> entries, final String nextToken) {
        this.resourceKey = resourceKey;
        this.entries = entries;
        this.nextToken = nextToken;
    }

    /**
     * Creates a non-terminal page result (there are more pages to follow).
     */
    public static <T> PaginationResult<T> of(final String resourceKey, final Map<String, T> entries, final PaginationCursor nextCursor) {
        return new PaginationResult<>(resourceKey, entries, nextCursor.token);
    }

    /**
     * Creates a terminal page result ({@code next_token} will be {@code null}).
     */
    public static <T> PaginationResult<T> last(final String resourceKey, final Map<String, T> entries) {
        return new PaginationResult<>(resourceKey, entries, null);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();

        if (nextToken == null) {
            builder.nullField(FIELD_NEXT_TOKEN);
        } else {
            builder.field(FIELD_NEXT_TOKEN, nextToken);
        }

        @SuppressWarnings("unchecked")
        final Map<String, ?> serialisable = DefaultObjectMapper.readValue(
            DefaultObjectMapper.writeValueAsString(entries, false),
            Map.class
        );
        builder.field(resourceKey, serialisable);

        builder.endObject();
        return builder;
    }

    @Override
    public boolean isFragment() {
        return false;
    }
}
