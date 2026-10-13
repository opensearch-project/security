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

import java.util.stream.Collectors;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.HitsMetadata;
import org.opensearch.client.opensearch.core.search.TotalHits;

class NumberOfTotalHitsIsEqualToMatcher extends TypeSafeDiagnosingMatcher<SearchResponse<?>> {

    private final int expectedNumberOfHits;

    NumberOfTotalHitsIsEqualToMatcher(int expectedNumberOfHits) {
        this.expectedNumberOfHits = expectedNumberOfHits;
    }

    @Override
    protected boolean matchesSafely(SearchResponse<?> searchResponse, Description mismatchDescription) {
        HitsMetadata<?> hits = searchResponse.hits();
        if (hits == null) {
            mismatchDescription.appendText("contains null hits");
            return false;
        }
        TotalHits totalHits = hits.total();
        if (totalHits == null) {
            mismatchDescription.appendText("Total hits number is null.");
            return false;
        }
        if (expectedNumberOfHits != totalHits.value()) {
            String documentIds = hits.hits().stream().map(hit -> hit.index() + "/" + hit.id()).collect(Collectors.joining(","));
            mismatchDescription.appendText("contains ")
                .appendValue(hits.hits().size())
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
