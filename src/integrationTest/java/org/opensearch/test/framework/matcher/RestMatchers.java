/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.test.framework.matcher;

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.databind.JsonNode;
import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;

import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

public class RestMatchers {

    private RestMatchers() {}

    public static HttpResponseMatcher isOk() {
        return new HttpResponseMatcher(200, "OK");
    }

    public static HttpResponseMatcher isCreated() {
        return new HttpResponseMatcher(201, "Created");
    }

    public static OpenSearchErrorHttpResponseMatcher isForbidden() {
        return new OpenSearchErrorHttpResponseMatcher(403, "Forbidden");
    }

    public static DiagnosingMatcher<HttpResponse> isForbidden(String jsonPointer, String patternString) {
        return isForbidden().withAttribute(jsonPointer, patternString);
    }

    public static OpenSearchErrorHttpResponseMatcher isBadRequest() {
        return new OpenSearchErrorHttpResponseMatcher(400, "Bad Request");
    }

    public static DiagnosingMatcher<HttpResponse> isBadRequest(String jsonPointer, String patternString) {
        return isBadRequest().withAttribute(jsonPointer, patternString);
    }

    public static OpenSearchErrorHttpResponseMatcher isNotImplemented() {
        return new OpenSearchErrorHttpResponseMatcher(501, "Not Implemented");
    }

    public static DiagnosingMatcher<HttpResponse> isMethodNotImplemented(String jsonPointer, String patternString) {
        return isNotImplemented().withAttribute(jsonPointer, patternString);
    }

    public static OpenSearchErrorHttpResponseMatcher isInternalServerError() {
        return new OpenSearchErrorHttpResponseMatcher(500, "Internal Server Error");
    }

    public static DiagnosingMatcher<HttpResponse> isInternalServerError(String jsonPointer, String patternString) {
        return isInternalServerError().withAttribute(jsonPointer, patternString);
    }

    public static OpenSearchErrorHttpResponseMatcher isNotFound() {
        return new OpenSearchErrorHttpResponseMatcher(404, "Not Found");
    }

    public static OpenSearchErrorHttpResponseMatcher isNotAllowed() {
        return new OpenSearchErrorHttpResponseMatcher(405, "Not Allowed");
    }

    public static OpenSearchErrorHttpResponseMatcher isUnauthorized() {
        return new OpenSearchErrorHttpResponseMatcher(401, "Unauthorized");
    }

    public static class HttpResponseMatcher extends DiagnosingMatcher<HttpResponse> {
        final int statusCode;
        final String statusName;

        HttpResponseMatcher(int statusCode, String statusName) {
            this.statusCode = statusCode;
            this.statusName = statusName;
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("Response has status " + statusCode + " " + statusName);
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            if (!(item instanceof HttpResponse response)) {
                mismatchDescription.appendValue(item).appendText(" is not a HttpResponse");
                return false;
            }

            if (response.getStatusCode() == this.statusCode) {
                return true;
            } else {
                mismatchDescription.appendText("Status is not " + statusCode + " " + statusName + ":\n").appendValue(item);
                return false;
            }
        }

        public int statusCode() {
            return this.statusCode;
        }

    }

    public static class OpenSearchErrorHttpResponseMatcher extends HttpResponseMatcher {
        final ImmutableMap<String, String> attributes;

        OpenSearchErrorHttpResponseMatcher(int statusCode, String statusName) {
            super(statusCode, statusName);
            this.attributes = ImmutableMap.of();
        }

        OpenSearchErrorHttpResponseMatcher(int statusCode, String statusName, ImmutableMap<String, String> attributes) {
            super(statusCode, statusName);
            this.attributes = attributes;
        }

        public OpenSearchErrorHttpResponseMatcher withReason(String reason) {
            return withAttribute("/error/reason", reason);
        }

        public OpenSearchErrorHttpResponseMatcher withType(String type) {
            return withAttribute("/error/type", type);
        }

        public OpenSearchErrorHttpResponseMatcher withAttribute(String jsonPointer, String value) {
            return new OpenSearchErrorHttpResponseMatcher(
                this.statusCode,
                this.statusName,
                ImmutableMap.<String, String>builder().putAll(this.attributes).put(jsonPointer, value).build()
            );
        }

        @Override
        public void describeTo(Description description) {
            super.describeTo(description);
            for (Map.Entry<String, String> entry : this.attributes.entrySet()) {
                description.appendText(" with " + entry.getKey() + " " + entry.getValue());
            }
        }

        @Override
        protected boolean matches(Object item, Description mismatchDescription) {
            if (!super.matches(item, mismatchDescription)) {
                return false;
            }

            HttpResponse response = (HttpResponse) item;
            boolean result = true;

            if (!this.attributes.isEmpty()) {
                JsonNode responseDocument;

                try {
                    responseDocument = response.bodyAsJsonNode();
                } catch (Exception e) {
                    mismatchDescription.appendText("Parsing request body failed with " + e).appendText("\n").appendValue(item);
                    return false;
                }

                for (Map.Entry<String, String> entry : this.attributes.entrySet()) {
                    String actualValue = responseDocument.at(entry.getKey()).asText();
                    String expectedValue = entry.getValue();
                    if (actualValue == null || !actualValue.contains(entry.getValue())) {
                        mismatchDescription.appendText(entry.getKey() + " is not " + expectedValue + ": ")
                            .appendValue(actualValue)
                            .appendText("\n");
                        result = false;
                    }
                }
            }

            if (!result) {
                mismatchDescription.appendValue(item);
            }

            return result;
        }

    }
}
