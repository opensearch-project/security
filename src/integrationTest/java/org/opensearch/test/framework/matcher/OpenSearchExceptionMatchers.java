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

import org.hamcrest.Matcher;

import org.opensearch.core.rest.RestStatus;

import static org.hamcrest.Matchers.containsString;

public class OpenSearchExceptionMatchers {

    private OpenSearchExceptionMatchers() {}

    public static Matcher<Throwable> statusException(RestStatus expectedRestStatus) {
        return new OpenSearchStatusExceptionMatcher(expectedRestStatus);
    }

    public static Matcher<Throwable> errorMessage(Matcher<String> errorMessageMatcher) {
        return new ExceptionErrorMessageMatcher(errorMessageMatcher);
    }

    public static Matcher<Throwable> errorMessageContain(String errorMessage) {
        return errorMessage(containsString(errorMessage));
    }

    public static Matcher<Throwable> hasCause(Class<? extends Throwable> clazz) {
        return new ExceptionHasCauseMatcher(clazz);
    }
}
