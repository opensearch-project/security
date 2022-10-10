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

import java.util.Optional;

import org.hamcrest.Matcher;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHits;

public class SearchResponseMatchers {

	private SearchResponseMatchers() {}

	public static Matcher<SearchResponse> isSuccessfulSearchResponse() {
		return new SuccessfulSearchResponseMatcher();
	}

	public static Matcher<SearchResponse> numberOfTotalHitsIsEqualTo(int expectedNumberOfHits) {
		return new NumberOfTotalHitsIsEqualToMatcher(expectedNumberOfHits);
	}

	public static Matcher<SearchResponse> numberOfHitsInPageIsEqualTo(int expectedNumberOfHits) {
		return new NumberOfHitsInPageIsEqualToMatcher(expectedNumberOfHits);
	}

	public static <T> Matcher<SearchResponse> searchHitContainsFieldWithValue(int hitIndex, String fieldName, T expectedValue) {
		return new SearchHitContainsFieldWithValueMatcher<>(hitIndex, fieldName, expectedValue);
	}

	public static Matcher<SearchResponse> searchHitsContainDocumentWithId(int hitIndex, String indexName, String documentId) {
		return new SearchHitsContainDocumentWithIdMatcher(hitIndex, indexName, documentId);
	}

	public static Matcher<SearchResponse> restStatusIs(RestStatus expectedRestStatus) {
		return new SearchResponseWithStatusCodeMatcher(expectedRestStatus);
	}

	public static Matcher<SearchResponse> containNotEmptyScrollingId() {
		return new ContainNotEmptyScrollingIdMatcher();
	}

	public static Matcher<SearchResponse> containAggregationWithNameAndType(String expectedAggregationName, String expectedAggregationType) {
		return new ContainsAggregationWithNameAndTypeMatcher(expectedAggregationName, expectedAggregationType);
	}

	static Long readTotalHits(SearchResponse searchResponse) {
		return Optional.ofNullable(searchResponse)
			.map(SearchResponse::getHits)
			.map(SearchHits::getTotalHits)
			.map(totalHits -> totalHits.value)
			.orElse(null);
	}
}
