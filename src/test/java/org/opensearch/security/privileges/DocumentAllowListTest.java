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

package org.opensearch.security.privileges;

import org.junit.Test;

import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DocumentAllowListTest {

    @Test
    public void testIsAllowed_GetRequest_matchingEntry() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("my_index", "doc1");
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertTrue(DocumentAllowList.isAllowed(new GetRequest("my_index", "doc1"), threadContext));
    }

    @Test
    public void testIsAllowed_GetRequest_noMatch() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("my_index", "doc1");
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertFalse(DocumentAllowList.isAllowed(new GetRequest("my_index", "doc2"), threadContext));
    }

    @Test
    public void testIsAllowed_SearchRequest_wildcardEntry() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("my_index", "*");
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertTrue(DocumentAllowList.isAllowed(new SearchRequest("my_index"), threadContext));
    }

    @Test
    public void testIsAllowed_SearchRequest_noMatch() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("other_index", "*");
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertFalse(DocumentAllowList.isAllowed(new SearchRequest("my_index"), threadContext));
    }

    @Test
    public void testIsAllowed_SearchRequest_multipleIndices_allAllowed() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("index_a", "*");
        allowList.add("index_b", "*");
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertTrue(DocumentAllowList.isAllowed(new SearchRequest("index_a", "index_b"), threadContext));
    }

    @Test
    public void testIsAllowed_SearchRequest_multipleIndices_partialMatch() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("index_a", "*");
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertFalse(DocumentAllowList.isAllowed(new SearchRequest("index_a", "index_b"), threadContext));
    }

    @Test
    public void testIsAllowed_noHeader() {
        final var threadContext = new ThreadContext(Settings.EMPTY);

        assertFalse(DocumentAllowList.isAllowed(new GetRequest("my_index", "doc1"), threadContext));
        assertFalse(DocumentAllowList.isAllowed(new SearchRequest("my_index"), threadContext));
    }

    @Test
    public void testIsAllowed_DeleteRequest_wildcardEntry_returnsFalse() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("my_index", DocumentAllowList.WILDCARD_DOCUMENT_ID);
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertFalse(DocumentAllowList.isAllowed(new DeleteRequest("my_index", "doc1"), threadContext));
    }

    @Test
    public void testIsAllowed_IndexRequest_wildcardEntry_returnsFalse() {
        final var threadContext = new ThreadContext(Settings.EMPTY);
        final var allowList = new DocumentAllowList();
        allowList.add("my_index", DocumentAllowList.WILDCARD_DOCUMENT_ID);
        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER, allowList.toString());

        assertFalse(DocumentAllowList.isAllowed(new IndexRequest("my_index"), threadContext));
    }

    @Test
    public void testParseToString_roundTrip_withWildcard() {
        final var original = new DocumentAllowList();
        original.add("my_index", "*");
        original.add("other_index", "doc1");

        final var serialized = original.toString();
        final var parsed = DocumentAllowList.parse(serialized);

        assertThat(parsed, is(original));
    }

    @Test
    public void testParseToString_roundTrip_withSpecialChars() {
        final var original = new DocumentAllowList();
        original.add("my_index", "id/with|special\\chars");

        final var serialized = original.toString();
        final var parsed = DocumentAllowList.parse(serialized);

        assertThat(parsed, is(original));
        assertTrue(parsed.isAllowed("my_index", "id/with|special\\chars"));
    }
}
