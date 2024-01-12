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

import java.util.Map;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.SearchHit;

import static org.opensearch.test.framework.matcher.SearchResponseMatchers.readTotalHits;

class SearchHitContainsFieldWithValueMatcher<T> extends TypeSafeDiagnosingMatcher<SearchResponse> {

    private final int hitIndex;

    private final String fieldName;

    private final T expectedValue;

    SearchHitContainsFieldWithValueMatcher(int hitIndex, String fieldName, T expectedValue) {
        this.hitIndex = hitIndex;
        this.fieldName = fieldName;
        this.expectedValue = expectedValue;
    }

    @Override
    protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
        mismatchDescription.appendText("Unexpected match in SearchResponse " + searchResponse.toString() + "\n");
        Long numberOfHits = readTotalHits(searchResponse);
        if (numberOfHits == null) {
            mismatchDescription.appendText("Total number of hits is unknown.");
            return false;
        }
        if (hitIndex >= numberOfHits) {
            mismatchDescription.appendText("Search result contain only ").appendValue(numberOfHits).appendText(" hits");
            return false;
        }
        SearchHit searchHit = searchResponse.getHits().getAt(hitIndex);
        Map<String, Object> source = searchHit.getSourceAsMap();
        if (source == null) {
            mismatchDescription.appendText("Source document is null, is fetch source option set to true?");
            return false;
        }
        if (source.containsKey(fieldName) == false) {
            mismatchDescription.appendText("Document does not contain field ").appendValue(fieldName);
            return false;
        }
        Object actualValue = source.get(fieldName);
        if (!expectedValue.equals(actualValue)) {
            mismatchDescription.appendText("Field value is equal to ").appendValue(actualValue);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Search hit with index ")
            .appendValue(hitIndex)
            .appendText(" should contain field ")
            .appendValue(fieldName)
            .appendValue(" with value equal to ")
            .appendValue(expectedValue);
    }
}
