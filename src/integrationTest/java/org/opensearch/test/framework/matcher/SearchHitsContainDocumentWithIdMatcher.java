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
import org.opensearch.search.SearchHit;

import static org.opensearch.test.framework.matcher.SearchResponseMatchers.readTotalHits;

class SearchHitsContainDocumentWithIdMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    private final int hitIndex;
    private final String indexName;
    private final String id;

    public SearchHitsContainDocumentWithIdMatcher(int hitIndex, String indexName, String id) {
        this.hitIndex = hitIndex;
        this.indexName = indexName;
        this.id = id;
    }

    @Override
    protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
        Long numberOfHits = readTotalHits(searchResponse);
        if (numberOfHits == null) {
            mismatchDescription.appendText("Number of total hits is unknown.");
            return false;
        }
        if (hitIndex >= numberOfHits) {
            mismatchDescription.appendText("Search result contain only ").appendValue(numberOfHits).appendText(" hits");
            return false;
        }
        SearchHit searchHit = searchResponse.getHits().getAt(hitIndex);
        if (indexName.equals(searchHit.getIndex()) == false) {
            mismatchDescription.appendText("document is part of another index ").appendValue(indexName);
            return false;
        }
        if (id.equals(searchHit.getId()) == false) {
            mismatchDescription.appendText("Document has another id which is ").appendValue(searchHit.getId());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Search hit with index ")
            .appendValue(hitIndex)
            .appendText(" should contains document which is part of index ")
            .appendValue(indexName)
            .appendValue(" and has id ")
            .appendValue(id);
    }
}
