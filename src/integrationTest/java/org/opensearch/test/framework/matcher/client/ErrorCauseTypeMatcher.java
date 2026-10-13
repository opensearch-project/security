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

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch._types.ErrorCause;

import static java.util.Objects.requireNonNull;

class ErrorCauseTypeMatcher extends TypeSafeDiagnosingMatcher<ErrorCause> {

    private final Matcher<String> errorMessageMatcher;

    public ErrorCauseTypeMatcher(Matcher<String> errorMessageMatcher) {
        this.errorMessageMatcher = requireNonNull(errorMessageMatcher, "Error message matcher is required");
    }

    @Override
    protected boolean matchesSafely(ErrorCause err, Description mismatchDescription) {
        boolean matches = errorMessageMatcher.matches(err.type());
        if (matches == false) {
            mismatchDescription.appendText("Error of type ").appendValue(err.type()).appendText("contains unexpected type");
        }
        return matches;

    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Error type matches").appendValue(errorMessageMatcher);
    }
}
