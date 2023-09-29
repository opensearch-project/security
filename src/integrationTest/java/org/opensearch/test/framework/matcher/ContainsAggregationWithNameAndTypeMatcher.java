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
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.Aggregations;

import static java.util.Objects.requireNonNull;

class ContainsAggregationWithNameAndTypeMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    private final String expectedAggregationName;
    private final String expectedAggregationType;

    public ContainsAggregationWithNameAndTypeMatcher(String expectedAggregationName, String expectedAggregationType) {
        this.expectedAggregationName = requireNonNull(expectedAggregationName, "Aggregation name is required");
        this.expectedAggregationType = requireNonNull(expectedAggregationType, "Expected aggregation type is required.");
    }

    @Override
    protected boolean matchesSafely(SearchResponse response, Description mismatchDescription) {
        Aggregations aggregations = response.getAggregations();
        if (aggregations == null) {
            mismatchDescription.appendText("search response does not contain aggregations");
            return false;
        }
        Aggregation aggregation = aggregations.get(expectedAggregationName);
        if (aggregation == null) {
            mismatchDescription.appendText("Response does not contain aggregation with name ").appendValue(expectedAggregationName);
            return false;
        }
        if (expectedAggregationType.equals(aggregation.getType()) == false) {
            mismatchDescription.appendText("Aggregation contain incorrect type which is ").appendValue(aggregation.getType());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Search response should contains aggregation results with name ")
            .appendValue(expectedAggregationName)
            .appendText(" and type ")
            .appendValue(expectedAggregationType);
    }
}
