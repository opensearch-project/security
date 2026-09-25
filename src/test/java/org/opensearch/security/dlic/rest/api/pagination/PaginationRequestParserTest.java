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

import java.util.Map;

import org.junit.Test;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.util.FakeRestRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PaginationRequestParserTest {

    @Test
    public void isPaginationRequestedFalseWhenNoParams() {
        final var request = FakeRestRequest.builder().build();

        assertFalse(PaginationRequestParser.isPaginationRequested(request));
    }

    @Test
    public void isPaginationRequestedTrueForSizeParam() {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SIZE, "10")).build();

        assertTrue(PaginationRequestParser.isPaginationRequested(request));
    }

    @Test
    public void isPaginationRequestedTrueForSortParam() {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SORT, "asc")).build();

        assertTrue(PaginationRequestParser.isPaginationRequested(request));
    }

    @Test
    public void isPaginationRequestedTrueForNextTokenParam() {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_NEXT_TOKEN, "sometoken")).build();

        assertTrue(PaginationRequestParser.isPaginationRequested(request));
    }

    @Test
    public void parseWithNoParamsUsesDefaults() throws Exception {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SIZE, "50")).build();
        final PaginationParams[] params = new PaginationParams[1];

        final var result = PaginationRequestParser.parse(request);
        assertTrue(result.isValid());
        result.valid(p -> params[0] = p);

        assertThat(params[0].size, is(50));
        assertThat(params[0].sort, is(PaginationParams.SORT_ASC));
        assertNull(params[0].nextToken);
    }

    @Test
    public void parseDefaultsSizeWhenOnlySortProvided() throws Exception {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SORT, "desc")).build();
        final PaginationParams[] params = new PaginationParams[1];

        final var result = PaginationRequestParser.parse(request);
        assertTrue(result.isValid());
        result.valid(p -> params[0] = p);

        assertThat(params[0].size, is(PaginationParams.DEFAULT_SIZE));
        assertThat(params[0].sort, is(PaginationParams.SORT_DESC));
    }

    @Test
    public void parsePreservesNextToken() throws Exception {
        final var token = PaginationCursor.encode(CType.ROLES, PaginationParams.SORT_ASC, "role_a").token;
        final var request = FakeRestRequest.builder()
            .withParams(Map.of(PaginationRequestParser.PARAM_SIZE, "5", PaginationRequestParser.PARAM_NEXT_TOKEN, token))
            .build();
        final PaginationParams[] params = new PaginationParams[1];

        PaginationRequestParser.parse(request).valid(p -> params[0] = p);

        assertThat(params[0].nextToken, is(token));
        assertTrue(params[0].hasCursor());
    }

    @Test
    public void parseRejectsZeroSize() {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SIZE, "0")).build();

        final var result = PaginationRequestParser.parse(request);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseRejectsNegativeSize() {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SIZE, "-1")).build();

        final var result = PaginationRequestParser.parse(request);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseRejectsSizeAboveMax() {
        final var request = FakeRestRequest.builder()
            .withParams(Map.of(PaginationRequestParser.PARAM_SIZE, String.valueOf(PaginationParams.MAX_SIZE + 1)))
            .build();

        final var result = PaginationRequestParser.parse(request);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAcceptsMaxSize() throws Exception {
        final var request = FakeRestRequest.builder()
            .withParams(Map.of(PaginationRequestParser.PARAM_SIZE, String.valueOf(PaginationParams.MAX_SIZE)))
            .build();

        final var result = PaginationRequestParser.parse(request);

        assertTrue(result.isValid());
    }

    @Test
    public void parseRejectsNonIntegerSize() {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SIZE, "abc")).build();

        final var result = PaginationRequestParser.parse(request);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }

    @Test
    public void parseAcceptsAsc() throws Exception {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SORT, "asc")).build();

        assertTrue(PaginationRequestParser.parse(request).isValid());
    }

    @Test
    public void parseAcceptsDesc() throws Exception {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SORT, "desc")).build();

        assertTrue(PaginationRequestParser.parse(request).isValid());
    }

    @Test
    public void parseRejectsInvalidSort() {
        final var request = FakeRestRequest.builder().withParams(Map.of(PaginationRequestParser.PARAM_SORT, "random")).build();

        final var result = PaginationRequestParser.parse(request);

        assertFalse(result.isValid());
        assertThat(result.status(), is(RestStatus.BAD_REQUEST));
    }
}
