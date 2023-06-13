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

import org.opensearch.action.search.MultiSearchResponse;

class SuccessfulMultiSearchResponseMatcher extends TypeSafeDiagnosingMatcher<MultiSearchResponse> {

    @Override
    protected boolean matchesSafely(MultiSearchResponse response, Description mismatchDescription) {
        for (MultiSearchResponse.Item itemResponse : response.getResponses()) {
            if (itemResponse.isFailure()) {
                mismatchDescription.appendValue("Get an item failed: ").appendValue(itemResponse.getFailureMessage());
                return false;
            }
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful multi search response");
    }
}
