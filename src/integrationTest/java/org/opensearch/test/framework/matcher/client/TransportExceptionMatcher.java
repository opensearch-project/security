/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.matcher.client;

import java.io.IOException;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.transport.TransportException;
import org.opensearch.client.transport.httpclient5.ResponseException;
import org.opensearch.core.rest.RestStatus;

import static java.util.Objects.requireNonNull;

class TransportExceptionMatcher extends TypeSafeDiagnosingMatcher<Throwable> {

    private final RestStatus expectedRestStatus;

    public TransportExceptionMatcher(RestStatus expectedRestStatus) {
        this.expectedRestStatus = requireNonNull(expectedRestStatus, "Expected rest status is required.");
    }

    @Override
    protected boolean matchesSafely(Throwable throwable, Description mismatchDescription) {
        Throwable cause = throwable;

        if (cause instanceof IOException && cause.getCause() != null) {
            cause = cause.getCause();
        }

        if (cause instanceof TransportException && cause.getCause() != null) {
            cause = cause.getCause();
        }

        if (cause instanceof OpenSearchException ose) {
            if (expectedRestStatus.getStatus() != ose.status()) {
                mismatchDescription.appendText("actual status code is ")
                    .appendValue(ose.status())
                    .appendText(", error message ")
                    .appendValue(cause.getMessage());
                return false;
            } else {
                return true;
            }
        }

        if ((cause instanceof ResponseException) == false) {
            mismatchDescription.appendText("actual exception type is ")
                .appendValue(cause.getClass().getCanonicalName())
                .appendText(", error message ")
                .appendValue(cause.getMessage());
            return false;
        }
        ResponseException openSearchException = (ResponseException) cause;
        if (expectedRestStatus.getStatus() != openSearchException.status()) {
            mismatchDescription.appendText("actual status code is ")
                .appendValue(openSearchException.status())
                .appendText(", error message ")
                .appendValue(cause.getMessage());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("OpenSearchException with status code ").appendValue(expectedRestStatus);
    }
}
