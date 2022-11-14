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
import java.util.Set;
import java.util.stream.Stream;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;

import static java.util.Objects.isNull;
import static java.util.Objects.requireNonNull;

class SearchHitsDocumentsContainExactlyFieldsWithNamesMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

	private String expectedIndexName;
	private Set<String> expectedFieldsNames;

	SearchHitsDocumentsContainExactlyFieldsWithNamesMatcher(String expectedIndexName, String... expectedFieldsNames) {
		this.expectedIndexName = requireNonNull(expectedIndexName, "expectedIndexName is required");
		if (isNull(expectedFieldsNames) || expectedFieldsNames.length == 0) {
			throw new IllegalArgumentException("expectedFieldsNames cannot be null or empty");
		}
		this.expectedFieldsNames = Set.of(expectedFieldsNames);
	}

	@Override protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
		SearchHits searchHits = searchResponse.getHits();
		boolean containsAnyHitForIndex = Stream.of(searchHits.getHits()).anyMatch(searchHit -> expectedIndexName.equals(searchHit.getIndex()));
		if (!containsAnyHitForIndex) {
			mismatchDescription.appendText("Response does not contain any hit for given index");
			return false;
		}
		for (SearchHit searchHit : searchHits.getHits()) {
			if (expectedIndexName.equals(searchHit.getIndex())) {
				Map<String, Object> hitSourceMap = searchHit.getSourceAsMap();
				Set<String> actualFieldsNames = hitSourceMap.keySet();
				if (!expectedFieldsNames.equals(actualFieldsNames)) {
					mismatchDescription
							.appendValue("Actual search hit with docId: ").appendValue(searchHit.getId())
							.appendText(" contains fields with names: ").appendValue(actualFieldsNames);
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("Index: ").appendValue(expectedIndexName)
				.appendText(". Search hits should contain exactly fields with names: ").appendValue(expectedFieldsNames);
	}
}
