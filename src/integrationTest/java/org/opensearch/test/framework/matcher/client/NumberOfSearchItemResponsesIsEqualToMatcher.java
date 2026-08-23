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
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.core.MsearchResponse;

class NumberOfSearchItemResponsesIsEqualToMatcher extends TypeSafeDiagnosingMatcher<MsearchResponse<?>> {

    private final int expectedNumberOfResponses;

    NumberOfSearchItemResponsesIsEqualToMatcher(int expectedNumberOfResponses) {
        this.expectedNumberOfResponses = expectedNumberOfResponses;
    }

    @Override
    protected boolean matchesSafely(MsearchResponse<?> response, Description mismatchDescription) {
        if (expectedNumberOfResponses != response.responses().size()) {
            mismatchDescription.appendText("Actual number of responses: ").appendValue(response.responses().size());
            return false;
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Multi search response contains: ").appendValue(expectedNumberOfResponses).appendText(" item responses");
    }
}
