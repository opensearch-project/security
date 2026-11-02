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

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.opensearch.security.securityconf.impl.CType;

/**
 * Stateless utility that applies high-performance cursor-based pagination to a fully-processed
 * (authorized, redacted, filtered) Security configuration entry map.
 *
 */
public final class Paginator {

    private Paginator() {}

    /**
     * Paginates the entry map.
     *
     * @param allEntries fully-processed, caller-visible entries (key = entity name)
     * @param params     validated pagination parameters
     * @param cursor     pre-validated cursor from a prior page
     * @param ctype      configuration type
     * @return a {@link PaginationResult}
     */
    public static <T> PaginationResult<T> paginate(
        final Map<String, T> allEntries,
        final PaginationParams params,
        final PaginationCursor cursor,
        final CType<?> ctype
    ) {
        Objects.requireNonNull(allEntries, "allEntries must not be null");
        Objects.requireNonNull(params, "params must not be null");
        Objects.requireNonNull(ctype, "ctype must not be null");

        final String resourceKey = ctype.toLCString();

        if (allEntries.isEmpty()) {
            return PaginationResult.last(resourceKey, Map.of());
        }

        final boolean isDesc = PaginationParams.SORT_DESC.equals(params.sort);
        final String lastKey = (cursor != null) ? cursor.lastKey : null;

        // Filter first
        Stream<Map.Entry<String, T>> entryStream = allEntries.entrySet().stream();
        if (lastKey != null && !lastKey.isEmpty()) {
            entryStream = entryStream.filter(entry -> {
                final int cmp = entry.getKey().compareTo(lastKey);
                return isDesc ? cmp < 0 : cmp > 0;
            });
        }

        // Sort the filtered items
        Comparator<Map.Entry<String, T>> comparator = Map.Entry.comparingByKey();
        if (isDesc) {
            comparator = comparator.reversed();
        }
        final int targetSize = params.size;
        final List<Map.Entry<String, T>> candidatePage = entryStream.sorted(comparator).limit(targetSize + 1L).collect(Collectors.toList());

        final boolean hasNextPage = candidatePage.size() > targetSize;
        final int pageSize = hasNextPage ? targetSize : candidatePage.size();

        final Map<String, T> pageMap = new LinkedHashMap<>((int) Math.ceil(pageSize / 0.75f));
        for (int i = 0; i < pageSize; i++) {
            final Map.Entry<String, T> entry = candidatePage.get(i);
            pageMap.put(entry.getKey(), entry.getValue());
        }

        if (hasNextPage) {
            final String newLastKey = candidatePage.get(pageSize - 1).getKey();
            return PaginationResult.of(resourceKey, pageMap, PaginationCursor.encode(ctype, params.sort, newLastKey));
        }

        return PaginationResult.last(resourceKey, pageMap);
    }
}
