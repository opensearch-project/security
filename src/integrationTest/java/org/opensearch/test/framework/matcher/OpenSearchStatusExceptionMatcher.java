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
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.OpenSearchException;
import org.opensearch.core.rest.RestStatus;

import static java.util.Objects.requireNonNull;

class OpenSearchStatusExceptionMatcher extends TypeSafeDiagnosingMatcher<Throwable> {

    private final RestStatus expectedRestStatus;

    public OpenSearchStatusExceptionMatcher(RestStatus expectedRestStatus) {
        this.expectedRestStatus = requireNonNull(expectedRestStatus, "Expected rest status is required.");
    }

    @Override
    protected boolean matchesSafely(Throwable throwable, Description mismatchDescription) {
        if ((throwable instanceof OpenSearchException) == false) {
            mismatchDescription.appendText("actual exception type is ")
                .appendValue(throwable.getClass().getCanonicalName())
                .appendText(", error message ")
                .appendValue(throwable.getMessage());
            return false;
        }
        OpenSearchException openSearchException = (OpenSearchException) throwable;
        if (expectedRestStatus.equals(openSearchException.status()) == false) {
            mismatchDescription.appendText("actual status code is ")
                .appendValue(openSearchException.status())
                .appendText(", error message ")
                .appendValue(throwable.getMessage());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("OpenSearchException with status code ").appendValue(expectedRestStatus);
    }
}
