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

import java.util.Map;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.Hit;

import static java.util.Objects.requireNonNull;
import static org.opensearch.test.framework.matcher.client.SearchResponseMatchers.readTotalHits;

class SearchHitDoesNotContainFieldMatcher extends TypeSafeDiagnosingMatcher<SearchResponse<?>> {

    private final int hitIndex;

    private final String fieldName;

    public SearchHitDoesNotContainFieldMatcher(int hitIndex, String fieldName) {
        this.hitIndex = hitIndex;
        this.fieldName = requireNonNull(fieldName, "Field name is required.");
    }

    @Override
    protected boolean matchesSafely(SearchResponse<?> searchResponse, Description mismatchDescription) {
        Long numberOfHits = readTotalHits(searchResponse);
        if (numberOfHits == null) {
            mismatchDescription.appendText("Total number of hits is unknown.");
            return false;
        }
        if (hitIndex >= numberOfHits) {
            mismatchDescription.appendText("Search result contain only ").appendValue(numberOfHits).appendText(" hits");
            return false;
        }
        Hit<?> searchHit = searchResponse.hits().hits().get(hitIndex);
        Map<String, Object> source = (Map<String, Object>) searchHit.source();
        if (source == null) {
            mismatchDescription.appendText("Source document is null, is fetch source option set to true?");
            return false;
        }
        if (source.containsKey(fieldName)) {
            mismatchDescription.appendText(" document contains field ").appendValue(fieldName);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("search hit with index ")
            .appendValue(hitIndex)
            .appendText(" does not contain field ")
            .appendValue(fieldName);
    }
}
