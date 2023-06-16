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

import java.util.Objects;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

class ExceptionHasCauseMatcher extends TypeSafeDiagnosingMatcher<Throwable> {

    private final Class<? extends Throwable> expectedCauseType;

    public ExceptionHasCauseMatcher(Class<? extends Throwable> expectedCauseType) {
        this.expectedCauseType = Objects.requireNonNull(expectedCauseType, "Exception cause type is required");
    }

    @Override
    protected boolean matchesSafely(Throwable throwable, Description mismatchDescription) {
        Throwable cause = throwable.getCause();
        if (cause == null) {
            mismatchDescription.appendText("exception cause is null");
            return false;
        }
        if (expectedCauseType.isInstance(cause) == false) {
            mismatchDescription.appendText(" cause is instance of ").appendValue(cause.getClass());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Exception cause is instance of ").appendValue(expectedCauseType);
    }
}
