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

import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.CType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class PaginationCursorTest {

    @Test
    public void encodeProducesTokenWithLastKey() throws Exception {
        final var cursor = PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, "role_a");

        assertThat(cursor.lastKey, is("role_a"));
        assertThat(cursor.token, not(nullValue()));
    }

    @Test
    public void encodeRejectsNullLastKey() {
        assertThrows(NullPointerException.class, () -> PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, null));
    }

    @Test
    public void roundTripAscending() throws Exception {
        final var encoded = PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, "role_z");
        final PaginationCursor[] decoded = new PaginationCursor[1];

        final var result = PaginationCursor.decode(encoded.token, CType.ROLES, PaginationParams.SORT_ASC);
        assertTrue(result.isValid());
        result.valid(c -> decoded[0] = c);

        assertThat(decoded[0].lastKey, is("role_z"));
        assertThat(decoded[0].token, is(encoded.token));
    }

    @Test
    public void roundTripDescending() throws Exception {
        final var encoded = PaginationCursor.encode(CType.INTERNALUSERS, PaginationParams.SORT_DESC, "user_m");
        final PaginationCursor[] decoded = new PaginationCursor[1];

        final var result = PaginationCursor.decode(encoded.token, CType.INTERNALUSERS, PaginationParams.SORT_DESC);
        assertTrue(result.isValid());
        result.valid(c -> decoded[0] = c);

        assertThat(decoded[0].lastKey, is("user_m"));
    }

    @Test
    public void decodeRejectsInvalidToken() {
        final var result = PaginationCursor.decode("not-base64!!!", CType.ROLES, PaginationParams.SORT_ASC);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void decodeRejectsNonJsonPayload() {
        final var encoded = Base64.getUrlEncoder().withoutPadding().encodeToString("hello world".getBytes(StandardCharsets.UTF_8));

        final var result = PaginationCursor.decode(encoded, CType.ROLES, PaginationParams.SORT_ASC);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void decodeRejectsMissingField() {
        // JSON object but last_key absent
        final var encoded = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("{\"ctype\":\"roles\",\"sort\":\"asc\"}".getBytes(StandardCharsets.UTF_8));

        final var result = PaginationCursor.decode(encoded, CType.ROLES, PaginationParams.SORT_ASC);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void decodeRejectsEmptyFieldValue() {
        // last_key is present but blank
        final var encoded = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("{\"ctype\":\"roles\",\"sort\":\"asc\",\"last_key\":\"\"}".getBytes(StandardCharsets.UTF_8));

        final var result = PaginationCursor.decode(encoded, CType.ROLES, PaginationParams.SORT_ASC);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void decodeRejectsCrossEndpointToken() {
        // cursor issued for ROLES but presented to TENANTS
        final var cursor = PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, "role_a");

        final var result = PaginationCursor.decode(cursor.token, CType.TENANTS, PaginationParams.SORT_ASC);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void decodeRejectsSortDirectionMismatch() {
        final var cursor = PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, "role_a");

        final var result = PaginationCursor.decode(cursor.token, CType.ROLES, PaginationParams.SORT_DESC);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }
}
