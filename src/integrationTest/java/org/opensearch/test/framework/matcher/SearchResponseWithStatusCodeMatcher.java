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

import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;

class SearchResponseWithStatusCodeMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    private final RestStatus expectedRestStatus;

    public SearchResponseWithStatusCodeMatcher(RestStatus expectedRestStatus) {
        this.expectedRestStatus = expectedRestStatus;
    }

    @Override
    protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
        if (expectedRestStatus.equals(searchResponse.status()) == false) {
            mismatchDescription.appendText("actual response status is ").appendValue(searchResponse.status());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Expected response status is ").appendValue(expectedRestStatus);
    }
}
