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
import org.opensearch.search.SearchHits;

class NumberOfHitsInPageIsEqualToMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    private final int expectedNumberOfHits;

    public NumberOfHitsInPageIsEqualToMatcher(int expectedNumberOfHits) {
        this.expectedNumberOfHits = expectedNumberOfHits;
    }

    @Override
    protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
        SearchHits hits = searchResponse.getHits();
        if ((hits == null) || (hits.getHits() == null)) {
            mismatchDescription.appendText("contains null hits");
            return false;
        }
        int actualNumberOfHits = hits.getHits().length;
        if (expectedNumberOfHits != actualNumberOfHits) {
            mismatchDescription.appendText("actual number of hits is equal to ").appendValue(actualNumberOfHits);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Number of hits on current page should be equal to ").appendValue(expectedNumberOfHits);
    }
}
