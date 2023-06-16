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

import static java.util.Objects.requireNonNull;

class ExceptionErrorMessageMatcher extends TypeSafeDiagnosingMatcher<Throwable> {

    private final Matcher<String> errorMessageMatcher;

    public ExceptionErrorMessageMatcher(Matcher<String> errorMessageMatcher) {
        this.errorMessageMatcher = requireNonNull(errorMessageMatcher, "Error message matcher is required");
    }

    @Override
    protected boolean matchesSafely(Throwable ex, Description mismatchDescription) {
        boolean matches = errorMessageMatcher.matches(ex.getMessage());
        if (matches == false) {
            mismatchDescription.appendText("Exception of class ")
                .appendValue(ex.getClass().getCanonicalName())
                .appendText("contains unexpected error message which is ")
                .appendValue(ex.getMessage());
        }
        return matches;

    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Error message in exception matches").appendValue(errorMessageMatcher);
    }
}
