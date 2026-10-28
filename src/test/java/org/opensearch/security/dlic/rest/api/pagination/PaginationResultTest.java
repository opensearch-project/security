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

import org.junit.Test;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.impl.CType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class PaginationResultTest {

    private static tools.jackson.databind.JsonNode toJson(final ToXContent result) throws IOException {
        try (final var builder = XContentFactory.jsonBuilder()) {
            result.toXContent(builder, ToXContent.EMPTY_PARAMS);
            return DefaultObjectMapper.readTree(builder.toString());
        }
    }

    @Test
    public void terminalPageHasNullNextTokenInJson() throws IOException {
        final var result = PaginationResult.last("roles", Map.of("role_a", "v"));

        final var json = toJson(result);

        assertTrue("next_token must be present as null", json.has("next_token"));
        assertTrue("next_token must be JSON null", json.get("next_token").isNull());
    }

    @Test
    public void terminalPageContainsResourceKey() throws IOException {
        final var result = PaginationResult.last("roles", Map.of("role_a", "v"));

        final var json = toJson(result);

        assertTrue("resource key 'roles' must be present", json.has("roles"));
    }

    @Test
    public void terminalPageEntriesAreSerialized() throws IOException {
        final var result = PaginationResult.last("roles", Map.of("role_a", "val_a"));

        final var json = toJson(result);

        assertNotNull(json.get("roles").get("role_a"));
    }

    @Test
    public void isFragmentReturnsFalse() {
        final var result = PaginationResult.last("roles", Map.of());
        assertFalse(result.isFragment());
    }

    @Test
    public void nonTerminalPageContainsNextToken() throws IOException {
        final var cursor = PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, "role_a");
        final var result = PaginationResult.of("roles", Map.of("role_a", "v"), cursor);

        final var json = toJson(result);

        assertFalse("next_token must not be null for non-terminal page", json.get("next_token").isNull());
        assertThat(json.get("next_token").asText(), is(cursor.token));
    }

    @Test
    public void nonTerminalPageResourceKeyMatchesCType() throws IOException {
        final var cursor = PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, "role_a");
        final var result = PaginationResult.of("roles", Map.of("role_a", "v"), cursor);

        final var json = toJson(result);

        assertTrue(json.has("roles"));
    }

    @Test
    public void emptyEntriesProducesEmptyObject() throws IOException {
        final var result = PaginationResult.last("roles", Map.of());

        final var json = toJson(result);

        assertThat(json.get("roles").size(), is(0));
        assertThat(result.nextToken, nullValue());
    }
}
