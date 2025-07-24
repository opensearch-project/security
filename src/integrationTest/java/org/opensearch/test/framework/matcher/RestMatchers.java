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

import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;

import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

public class RestMatchers {

    private RestMatchers() {}

    public static DiagnosingMatcher<HttpResponse> isOk() {
        return new DiagnosingMatcher<HttpResponse>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("Response has status 200 OK");
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof HttpResponse)) {
                    mismatchDescription.appendValue(item).appendText(" is not a HttpResponse");
                    return false;
                }

                HttpResponse response = (HttpResponse) item;

                if (response.getStatusCode() == 200) {
                    return true;
                } else {
                    mismatchDescription.appendText("Status is not 200 OK: ").appendValue(item);
                    return false;
                }

            }

        };
    }

    public static DiagnosingMatcher<HttpResponse> isForbidden(String jsonPointer, String patternString) {
        return new DiagnosingMatcher<HttpResponse>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("Response has status 403 Forbidden with a JSON response that has the value ")
                    .appendValue(patternString)
                    .appendText(" at ")
                    .appendValue(jsonPointer);
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof HttpResponse)) {
                    mismatchDescription.appendValue(item).appendText(" is not a HttpResponse");
                    return false;
                }

                HttpResponse response = (HttpResponse) item;

                if (response.getStatusCode() != 403) {
                    mismatchDescription.appendText("Status is not 403 Forbidden: ").appendText("\n").appendValue(item);
                    return false;
                }

                try {
                    String value = response.getTextFromJsonBody(jsonPointer);

                    if (value == null) {
                        mismatchDescription.appendText("Could not find value at " + jsonPointer).appendText("\n").appendValue(item);
                        return false;
                    }

                    if (value.contains(patternString)) {
                        return true;
                    } else {
                        mismatchDescription.appendText("Value at " + jsonPointer + " does not match pattern: " + patternString + "\n")
                            .appendValue(item);
                        return false;
                    }
                } catch (Exception e) {
                    mismatchDescription.appendText("Parsing request body failed with " + e).appendText("\n").appendValue(item);
                    return false;
                }
            }
        };
    }

    public static DiagnosingMatcher<HttpResponse> isBadRequest(String jsonPointer, String patternString) {
        return new DiagnosingMatcher<HttpResponse>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("Response has status 400 Bad Request with a JSON response that has the value ")
                    .appendValue(patternString)
                    .appendText(" at ")
                    .appendValue(jsonPointer);
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof HttpResponse)) {
                    mismatchDescription.appendValue(item).appendText(" is not a HttpResponse");
                    return false;
                }

                HttpResponse response = (HttpResponse) item;

                if (response.getStatusCode() != 400) {
                    mismatchDescription.appendText("Status is not 400 Bad Request: ").appendText("\n").appendValue(item);
                    return false;
                }

                try {
                    String value = response.getTextFromJsonBody(jsonPointer);

                    if (value == null) {
                        mismatchDescription.appendText("Could not find value at " + jsonPointer).appendText("\n").appendValue(item);
                        return false;
                    }

                    if (value.contains(patternString)) {
                        return true;
                    } else {
                        mismatchDescription.appendText("Value at " + jsonPointer + " does not match pattern: " + patternString + "\n")
                            .appendValue(item);
                        return false;
                    }
                } catch (Exception e) {
                    mismatchDescription.appendText("Parsing request body failed with " + e).appendText("\n").appendValue(item);
                    return false;
                }
            }
        };
    }

    public static DiagnosingMatcher<HttpResponse> isInternalServerError(String jsonPointer, String patternString) {
        return new DiagnosingMatcher<HttpResponse>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("Response has status 500 Internal Server Error with a JSON response that has the value ")
                    .appendValue(patternString)
                    .appendText(" at ")
                    .appendValue(jsonPointer);
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof HttpResponse)) {
                    mismatchDescription.appendValue(item).appendText(" is not a HttpResponse");
                    return false;
                }

                HttpResponse response = (HttpResponse) item;

                if (response.getStatusCode() != 500) {
                    mismatchDescription.appendText("Status is not 500 Internal Server Error: ").appendText("\n").appendValue(item);
                    return false;
                }

                try {
                    String value = response.getTextFromJsonBody(jsonPointer);

                    if (value == null) {
                        mismatchDescription.appendText("Could not find value at " + jsonPointer).appendText("\n").appendValue(item);
                        return false;
                    }

                    if (value.contains(patternString)) {
                        return true;
                    } else {
                        mismatchDescription.appendText("Value at " + jsonPointer + " does not match pattern: " + patternString + "\n")
                            .appendValue(item);
                        return false;
                    }
                } catch (Exception e) {
                    mismatchDescription.appendText("Parsing request body failed with " + e).appendText("\n").appendValue(item);
                    return false;
                }
            }
        };
    }

    public static DiagnosingMatcher<HttpResponse> isNotFound() {
        return new DiagnosingMatcher<HttpResponse>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("Response has status 404 Not Found");
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof HttpResponse)) {
                    mismatchDescription.appendValue(item).appendText(" is not a HttpResponse");
                    return false;
                }

                HttpResponse response = (HttpResponse) item;

                if (response.getStatusCode() == 404) {
                    return true;
                } else {
                    mismatchDescription.appendText("Status is not 404 Not Found: ").appendValue(item);
                    return false;
                }

            }

        };
    }
}
