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

package org.opensearch.security.filter;

import java.util.List;
import java.util.Map;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.junit.Test;

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class SecurityResponseTests {

    /**
     * This test should check whether a basic constructor with the JSON content type is successfully converted to RestResponse
     */
    @Test
    public void testSecurityResponseHasSingleContentType() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_OK, null, "foo bar", XContentType.JSON.mediaType());
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
        assertThat(restResponse.contentType(), equalTo(XContentType.JSON.mediaType()));
    }

    /**
     * This test should check whether adding a new HTTP Header for the content type takes the argument or the added header (should take arg.)
     */
    @Test
    public void testSecurityResponseMultipleContentTypesUsesPassed() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_OK, null, "foo bar", XContentType.JSON.mediaType());
        response.addHeader(HttpHeaders.CONTENT_TYPE, BytesRestResponse.TEXT_CONTENT_TYPE);
        assertThat(response.getHeaders().get("Content-Type"), equalTo(List.of(BytesRestResponse.TEXT_CONTENT_TYPE)));
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo(XContentType.JSON.mediaType()));
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
    }

    /**
     * This test should check whether specifying no content type correctly uses plain text
     */
    @Test
    public void testSecurityResponseDefaultContentTypeIsText() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_OK, null, "foo bar");
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo(BytesRestResponse.TEXT_CONTENT_TYPE));
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
    }

    /**
     * This test checks whether adding a new ContentType header actually changes the converted content type header  (it should not)
     */
    @Test
    public void testSecurityResponseSetHeaderContentTypeDoesNothing() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_OK, null, "foo bar");
        response.addHeader(HttpHeaders.CONTENT_TYPE, XContentType.JSON.mediaType());
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo(BytesRestResponse.TEXT_CONTENT_TYPE));
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
    }

    /**
     * This test should check whether adding a multiple new HTTP Headers for the content type takes the argument or the added header (should take arg.)
     */
    @Test
    public void testSecurityResponseAddMultipleContentTypeHeaders() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_OK, null, "foo bar", XContentType.JSON.mediaType());
        response.addHeader(HttpHeaders.CONTENT_TYPE, BytesRestResponse.TEXT_CONTENT_TYPE);
        assertThat(response.getHeaders().get("Content-Type"), equalTo(List.of(BytesRestResponse.TEXT_CONTENT_TYPE)));
        response.addHeader(HttpHeaders.CONTENT_TYPE, "newContentType");
        assertThat(response.getHeaders().get("Content-Type"), equalTo(List.of(BytesRestResponse.TEXT_CONTENT_TYPE, "newContentType")));
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
    }

    /**
     * This test confirms that fake content types work for conversion
     */
    @Test
    public void testSecurityResponseFakeContentTypeArgumentPasses() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_OK, null, "foo bar", "testType");
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo("testType"));
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
    }

    /**
     * This test checks that types passed as part of the Headers parameter in the argument do not overwrite actual Content Type
     */
    @Test
    public void testSecurityResponseContentTypeInConstructorHeader() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_OK, Map.of("Content-Type", "testType"), "foo bar");
        assertThat(response.getHeaders().get("Content-Type"), equalTo(List.of("testType")));
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo(BytesRestResponse.TEXT_CONTENT_TYPE));
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
    }

    /**
     * This test confirms the same as above but with a conflicting content type arg
     */
    @Test
    public void testSecurityResponseContentTypeInConstructorHeaderConflicts() {
        final SecurityResponse response = new SecurityResponse(
            HttpStatus.SC_OK,
            Map.of("Content-Type", "testType"),
            "foo bar",
            XContentType.JSON.mediaType()
        );
        assertThat(response.getHeaders().get("Content-Type"), equalTo(List.of("testType")));
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo(XContentType.JSON.mediaType()));
        assertThat(restResponse.status(), equalTo(RestStatus.OK));
    }

    /**
     * This test should check whether unauthorized requests are converted properly
     */
    @Test
    public void testSecurityResponseUnauthorizedRequestWithPlainTextContentType() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_UNAUTHORIZED, null, "foo bar");
        response.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo(BytesRestResponse.TEXT_CONTENT_TYPE));
        assertThat(restResponse.status(), equalTo(RestStatus.UNAUTHORIZED));
    }

    /**
     * This test should check whether forbidden requests are converted properly
     */
    @Test
    public void testSecurityResponseForbiddenRequestWithPlainTextContentType() {
        final SecurityResponse response = new SecurityResponse(HttpStatus.SC_FORBIDDEN, null, "foo bar");
        response.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        final RestResponse restResponse = response.asRestResponse();
        assertThat(restResponse.contentType(), equalTo(BytesRestResponse.TEXT_CONTENT_TYPE));
        assertThat(restResponse.status(), equalTo(RestStatus.FORBIDDEN));
    }
}
