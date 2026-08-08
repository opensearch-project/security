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

import org.opensearch.action.pagination.PageParams;

/**
 * Parsed and validated pagination parameters extracted from an incoming request.
 */
public final class PaginationParams {

    public static final String SORT_ASC = PageParams.PARAM_ASC_SORT_VALUE;
    public static final String SORT_DESC = PageParams.PARAM_DESC_SORT_VALUE;
    public static final int DEFAULT_SIZE = 100;
    public static final int MAX_SIZE = 1000;

    /** Page size requested by the caller. */
    public final int size;

    /** Sort direction: {@code "asc"} or {@code "desc"}. */
    public final String sort;

    /**
     * cursor from the previous response.
     */
    public final String nextToken;

    public PaginationParams(final int size, final String sort, final String nextToken) {
        this.size = size;
        this.sort = sort;
        this.nextToken = nextToken;
    }

    /**
     * Returns {@code true} when a cursor was supplied, meaning this is a continuation page.
     */
    public boolean hasCursor() {
        return nextToken != null;
    }
}
