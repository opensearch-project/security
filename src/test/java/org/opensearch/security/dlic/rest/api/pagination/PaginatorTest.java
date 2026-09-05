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

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;

import org.opensearch.security.securityconf.impl.CType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class PaginatorTest {

    /** Builds an insertion-ordered map: a→val, b→val, … up to {@code count} entries. */
    private static Map<String, String> entries(int count) {
        final var map = new LinkedHashMap<String, String>();
        for (int i = 0; i < count; i++) {
            final String key = String.format("entry_%02d", i);
            map.put(key, "v" + i);
        }
        return map;
    }

    private static PaginationParams ascParams(int size) {
        return new PaginationParams(size, PaginationParams.SORT_ASC, null);
    }

    private static PaginationParams descParams(int size) {
        return new PaginationParams(size, PaginationParams.SORT_DESC, null);
    }

    @Test
    public void emptyCollectionReturnsEmptyTerminalPage() {
        final var result = Paginator.paginate(Map.of(), ascParams(10), null, CType.ROLES);

        assertTrue(result.entries.isEmpty());
        assertNull(result.nextToken);
    }

    @Test
    public void allEntriesFitOnOnePage() {
        final var result = Paginator.paginate(entries(3), ascParams(10), null, CType.ROLES);

        assertThat(result.entries.size(), is(3));
        assertNull("terminal page must have null nextToken", result.nextToken);
    }

    @Test
    public void resourceKeyMatchesCType() {
        final var result = Paginator.paginate(entries(1), ascParams(5), null, CType.ROLES);

        assertThat(result.resourceKey, is("roles"));
    }

    @Test
    public void firstPageOfTwoHasNextToken() {
        final var result = Paginator.paginate(entries(5), ascParams(2), null, CType.ROLES);

        assertThat(result.entries.size(), is(2));
        assertNotNull("non-terminal page must have a nextToken", result.nextToken);
        assertThat(result.entries.keySet(), contains("entry_00", "entry_01"));
    }

    @Test
    public void secondPageContinuesFromCursor() throws Exception {
        final var all = entries(5);
        final var page1 = Paginator.paginate(all, ascParams(2), null, CType.ROLES);

        // decode cursor from page1
        final PaginationCursor[] cursor = new PaginationCursor[1];
        PaginationCursor.decode(page1.nextToken, CType.ROLES, PaginationParams.SORT_ASC).valid(c -> cursor[0] = c);

        final var page2 = Paginator.paginate(all, ascParams(2), cursor[0], CType.ROLES);

        assertThat(page2.entries.keySet(), contains("entry_02", "entry_03"));
        assertNotNull(page2.nextToken);
    }

    @Test
    public void lastPageHasNullNextToken() throws Exception {
        final var all = entries(5);
        // page 1 (size=2) → page 2 (size=2) → page 3 (size=2) must be terminal
        var page = Paginator.paginate(all, ascParams(2), null, CType.ROLES);
        final PaginationCursor[] cursor = new PaginationCursor[1];
        PaginationCursor.decode(page.nextToken, CType.ROLES, PaginationParams.SORT_ASC).valid(c -> cursor[0] = c);

        page = Paginator.paginate(all, ascParams(2), cursor[0], CType.ROLES);
        PaginationCursor.decode(page.nextToken, CType.ROLES, PaginationParams.SORT_ASC).valid(c -> cursor[0] = c);

        page = Paginator.paginate(all, ascParams(2), cursor[0], CType.ROLES);

        assertThat(page.entries.keySet(), contains("entry_04"));
        assertNull("last page must have null nextToken", page.nextToken);
    }

    @Test
    public void fullTraversalCoversAllEntriesExactlyOnce() throws Exception {
        final var all = entries(7);
        final var seen = new LinkedHashMap<String, String>();
        PaginationCursor cursor = null;

        do {
            final var params = new PaginationParams(3, PaginationParams.SORT_ASC, null);
            final var page = Paginator.paginate(all, params, cursor, CType.ROLES);
            seen.putAll(page.entries);
            if (page.nextToken != null) {
                final PaginationCursor[] next = new PaginationCursor[1];
                PaginationCursor.decode(page.nextToken, CType.ROLES, PaginationParams.SORT_ASC).valid(c -> next[0] = c);
                cursor = next[0];
            } else {
                cursor = null;
            }
        } while (cursor != null);

        assertThat(seen.size(), is(all.size()));
        assertThat(seen.keySet(), is(all.keySet()));
    }

    @Test
    public void descendingFirstPageOrderIsReversed() {
        final var result = Paginator.paginate(entries(5), descParams(2), null, CType.ROLES);

        assertThat(result.entries.size(), is(2));
        assertThat(result.entries.keySet(), contains("entry_04", "entry_03"));
    }

    @Test
    public void descendingFullTraversalCoversAllEntries() throws Exception {
        final var all = entries(5);
        final var seen = new LinkedHashMap<String, String>();
        PaginationCursor cursor = null;

        do {
            final var params = new PaginationParams(2, PaginationParams.SORT_DESC, null);
            final var page = Paginator.paginate(all, params, cursor, CType.ROLES);
            seen.putAll(page.entries);
            if (page.nextToken != null) {
                final PaginationCursor[] next = new PaginationCursor[1];
                PaginationCursor.decode(page.nextToken, CType.ROLES, PaginationParams.SORT_DESC).valid(c -> next[0] = c);
                cursor = next[0];
            } else {
                cursor = null;
            }
        } while (cursor != null);

        assertThat(seen.size(), is(all.size()));
    }

    @Test
    public void continuationAfterDeletedCursorEntityUsesList() throws Exception {
        final var all = entries(5); // entry_00 … entry_04
        final var page1 = Paginator.paginate(all, ascParams(2), null, CType.ROLES);
        // cursor points to entry_01 (last of page 1)
        final PaginationCursor[] cursor = new PaginationCursor[1];
        PaginationCursor.decode(page1.nextToken, CType.ROLES, PaginationParams.SORT_ASC).valid(c -> cursor[0] = c);

        // Simulate deletion of entry_01 (the cursor entity) before requesting page 2
        final var reduced = new LinkedHashMap<>(all);
        reduced.remove("entry_01");

        // Should lexicographically continue from "entry_01" → next is entry_02
        final var page2 = Paginator.paginate(reduced, ascParams(2), cursor[0], CType.ROLES);

        assertFalse(page2.entries.containsKey("entry_01"));
        assertThat(page2.entries.keySet(), contains("entry_02", "entry_03"));
    }

    @Test
    public void additionAfterCursorDoesNotAppearOnCurrentPage() throws Exception {
        final var all = entries(4); // entry_00 … entry_03
        final var page1 = Paginator.paginate(all, ascParams(2), null, CType.ROLES);
        final PaginationCursor[] cursor = new PaginationCursor[1];
        PaginationCursor.decode(page1.nextToken, CType.ROLES, PaginationParams.SORT_ASC).valid(c -> cursor[0] = c);

        // Add entry_ZZ which sorts after everything
        final var augmented = new LinkedHashMap<>(all);
        augmented.put("entry_ZZ", "new");

        final var page2 = Paginator.paginate(augmented, ascParams(2), cursor[0], CType.ROLES);

        // entry_02, entry_03 come next; entry_ZZ would appear on a subsequent page
        assertFalse("entry added before cursor must not appear on this page", page2.entries.containsKey("entry_ZZ"));
        assertThat(page2.entries.keySet(), contains("entry_02", "entry_03"));
    }

    // ── null-safety ───────────────────────────────────────────────────────────
    @Test
    public void nullAllEntriesThrows() {
        assertThrows(NullPointerException.class, () -> Paginator.paginate(null, ascParams(5), null, CType.ROLES));
    }

    @Test
    public void nullParamsThrows() {
        assertThrows(NullPointerException.class, () -> Paginator.paginate(entries(3), null, null, CType.ROLES));
    }

    @Test
    public void nullCTypeThrows() {
        assertThrows(NullPointerException.class, () -> Paginator.paginate(entries(3), ascParams(5), null, null));
    }
}
