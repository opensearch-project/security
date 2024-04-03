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

import org.opensearch.action.get.MultiGetResponse;

class NumberOfGetItemResponsesIsEqualToMatcher extends TypeSafeDiagnosingMatcher<MultiGetResponse> {

    private final int expectedNumberOfResponses;

    NumberOfGetItemResponsesIsEqualToMatcher(int expectedNumberOfResponses) {
        this.expectedNumberOfResponses = expectedNumberOfResponses;
    }

    @Override
    protected boolean matchesSafely(MultiGetResponse response, Description mismatchDescription) {
        if (expectedNumberOfResponses != response.getResponses().length) {
            mismatchDescription.appendText("Actual number of responses: ").appendValue(response.getResponses().length);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Multi get response contains: ").appendValue(expectedNumberOfResponses).appendText(" item responses");
    }
}
