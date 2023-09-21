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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;

import static java.util.Objects.requireNonNull;

class SearchHitsContainDocumentsInAnyOrderMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    /**
    * Pair contain index name and document id
    */
    private final List<Pair<String, String>> documentIds;

    /**
    *
    * @param documentIds Pair contain index name and document id
    */
    public SearchHitsContainDocumentsInAnyOrderMatcher(List<Pair<String, String>> documentIds) {
        this.documentIds = requireNonNull(documentIds, "Document ids are required.");
    }

    @Override
    protected boolean matchesSafely(SearchResponse response, Description mismatchDescription) {
        SearchHits hits = response.getHits();
        if (hits == null) {
            mismatchDescription.appendText("Search response does not contains hits (null).");
            return false;
        }
        SearchHit[] hitsArray = hits.getHits();
        if (hitsArray == null) {
            mismatchDescription.appendText("Search hits array is null");
            return false;
        }
        Set<Pair<String, String>> actualDocumentIds = Arrays.stream(hitsArray)
            .map(result -> Pair.of(result.getIndex(), result.getId()))
            .collect(Collectors.toSet());
        for (Pair<String, String> desiredDocumentId : documentIds) {
            if (actualDocumentIds.contains(desiredDocumentId) == false) {
                mismatchDescription.appendText("search result does not contain document with id ")
                    .appendValue(desiredDocumentId.getKey())
                    .appendText("/")
                    .appendValue(desiredDocumentId.getValue());
                return false;
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        String documentIdsString = documentIds.stream()
            .map(pair -> pair.getKey() + "/" + pair.getValue())
            .collect(Collectors.joining(", "));
        description.appendText("Search response should contains following documents ").appendValue(documentIdsString);
    }
}
