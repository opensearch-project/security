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

import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.HitsMetadata;

class NumberOfHitsInPageIsEqualToMatcher extends TypeSafeDiagnosingMatcher<SearchResponse<?>> {

    private final int expectedNumberOfHits;

    public NumberOfHitsInPageIsEqualToMatcher(int expectedNumberOfHits) {
        this.expectedNumberOfHits = expectedNumberOfHits;
    }

    @Override
    protected boolean matchesSafely(SearchResponse<?> searchResponse, Description mismatchDescription) {
        HitsMetadata<?> hits = searchResponse.hits();
        if ((hits == null) || (hits.hits() == null)) {
            mismatchDescription.appendText("contains null hits");
            return false;
        }
        int actualNumberOfHits = hits.hits().size();
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
