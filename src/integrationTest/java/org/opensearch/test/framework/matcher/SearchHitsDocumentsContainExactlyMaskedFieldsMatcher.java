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
import org.opensearch.search.SearchHits;

import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Objects.isNull;
import static java.util.Objects.requireNonNull;

class SearchHitsDocumentsContainExactlyMaskedFieldsMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

	private String expectedIndexName;
	private String expectedMaskValue;
	private Set<String> expectedMaskedFieldsNames;

	SearchHitsDocumentsContainExactlyMaskedFieldsMatcher(String expectedIndexName, String expectedMaskValue, String... expectedMaskedFieldsNames) {
		this.expectedIndexName = requireNonNull(expectedIndexName, "expectedIndexName is required");
		this.expectedMaskValue = requireNonNull(expectedMaskValue, "expectedMaskValue is required");
		if (isNull(expectedMaskedFieldsNames) || expectedMaskedFieldsNames.length == 0) {
			throw new IllegalArgumentException("expectedMaskedFieldsNames cannot be null or empty");
		}
		this.expectedMaskedFieldsNames = Set.of(expectedMaskedFieldsNames);
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
				if (!hitSourceMap.keySet().containsAll(expectedMaskedFieldsNames)) {
					mismatchDescription
							.appendValue("Actual search hit with docId: ").appendValue(searchHit.getId())
							.appendText(" does not contain all of expected masked fields. Actual fields: ").appendValue(hitSourceMap.keySet());
					return false;
				}
				for (String fieldName : hitSourceMap.keySet()) {
					boolean shouldBeMasked = expectedMaskedFieldsNames.contains(fieldName);
					if (shouldBeMasked && !expectedMaskValue.equals(hitSourceMap.get(fieldName))) {
						mismatchDescription.appendValue("Actual search hit with docId: ").appendValue(searchHit.getId())
								.appendText(" contains field with with name: ").appendText(fieldName)
								.appendText(" that should be masked. Actual value: ").appendValue(hitSourceMap.get(fieldName));
						return false;
					}
					if (!shouldBeMasked && expectedMaskValue.equals(hitSourceMap.get(fieldName))) {
						mismatchDescription.appendValue("Actual search hit with docId: ").appendValue(searchHit.getId())
								.appendText(" contains field with with name: ").appendText(fieldName)
								.appendText(" that should not be masked. Actual value: ").appendValue(hitSourceMap.get(fieldName));
						return false;
					}
				}
			}
		}
		return true;
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("Index: ").appendValue(expectedIndexName)
				.appendText(". Search hits should contain fields: ").appendValue(expectedMaskedFieldsNames)
				.appendText(" masked with: ").appendValue(expectedMaskValue);
	}
}
