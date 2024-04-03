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
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkResponse;

import static java.util.Objects.requireNonNull;

class BulkResponseContainExceptionsAtIndexMatcher extends TypeSafeDiagnosingMatcher<BulkResponse> {

    private final int errorIndex;
    private final Matcher<Throwable> exceptionMatcher;

    public BulkResponseContainExceptionsAtIndexMatcher(int errorIndex, Matcher<Throwable> exceptionMatcher) {
        this.errorIndex = errorIndex;
        this.exceptionMatcher = requireNonNull(exceptionMatcher, "Exception matcher is required.");
    }

    @Override
    protected boolean matchesSafely(BulkResponse response, Description mismatchDescription) {
        if (response.hasFailures() == false) {
            mismatchDescription.appendText("received successful bulk response what is not expected.");
            return false;
        }
        BulkItemResponse[] items = response.getItems();
        if ((items == null) || (items.length == 0) || (errorIndex >= items.length)) {
            mismatchDescription.appendText("bulk response does not contain item with index ").appendValue(errorIndex);
            return false;
        }
        BulkItemResponse item = items[errorIndex];
        if (item == null) {
            mismatchDescription.appendText("bulk item response with index ").appendValue(errorIndex).appendText(" is null.");
            return false;
        }
        BulkItemResponse.Failure failure = item.getFailure();
        if (failure == null) {
            mismatchDescription.appendText("bulk response item with index ")
                .appendValue(errorIndex)
                .appendText(" does not contain failure");
            return false;
        }
        Exception exception = failure.getCause();
        if (exception == null) {
            mismatchDescription.appendText("bulk response item with index ")
                .appendValue(errorIndex)
                .appendText(" does not contain exception.");
            return false;
        }
        if (exceptionMatcher.matches(exception) == false) {
            mismatchDescription.appendText("bulk response item with index ")
                .appendValue(errorIndex)
                .appendText(" contains incorrect exception which is ")
                .appendValue(exception);
            return false;
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("bulk response should contain exceptions which indicate failure");
    }
}
