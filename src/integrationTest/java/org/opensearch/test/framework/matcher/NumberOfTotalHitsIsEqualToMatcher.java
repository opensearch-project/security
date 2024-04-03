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

import java.util.Arrays;
import java.util.stream.Collectors;

import org.apache.lucene.search.TotalHits;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.SearchHits;

class NumberOfTotalHitsIsEqualToMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    private final int expectedNumberOfHits;

    NumberOfTotalHitsIsEqualToMatcher(int expectedNumberOfHits) {
        this.expectedNumberOfHits = expectedNumberOfHits;
    }

    @Override
    protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
        SearchHits hits = searchResponse.getHits();
        if (hits == null) {
            mismatchDescription.appendText("contains null hits");
            return false;
        }
        TotalHits totalHits = hits.getTotalHits();
        if (totalHits == null) {
            mismatchDescription.appendText("Total hits number is null.");
            return false;
        }
        if (expectedNumberOfHits != totalHits.value) {
            String documentIds = Arrays.stream(searchResponse.getHits().getHits())
                .map(hit -> hit.getIndex() + "/" + hit.getId())
                .collect(Collectors.joining(","));
            mismatchDescription.appendText("contains ")
                .appendValue(hits.getHits().length)
                .appendText(" hits, found document ids ")
                .appendValue(documentIds);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Search response should contains ").appendValue(expectedNumberOfHits).appendText(" hits");
    }
}
