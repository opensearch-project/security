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
import org.opensearch.action.get.GetResponse;

import java.util.Map;
import java.util.Set;

import static java.util.Objects.isNull;
import static java.util.Objects.requireNonNull;

class GetResponseDocumentContainsExactlyMaskedFieldsMatcher extends TypeSafeDiagnosingMatcher<GetResponse> {

    private final String expectedMaskValue;
    private final Set<String> expectedMaskedFieldsNames;

    GetResponseDocumentContainsExactlyMaskedFieldsMatcher(String expectedMaskValue, String... expectedMaskedFieldsNames) {
        this.expectedMaskValue = requireNonNull(expectedMaskValue, "expectedMaskValue is required");
        if (isNull(expectedMaskedFieldsNames) || expectedMaskedFieldsNames.length == 0) {
            throw new IllegalArgumentException("expectedMaskedFieldsNames cannot be null or empty");
        }
        this.expectedMaskedFieldsNames = Set.of(expectedMaskedFieldsNames);
    }

    @Override
    protected boolean matchesSafely(GetResponse response, Description mismatchDescription) {
        Map<String, Object> sourceMap = response.getSourceAsMap();
        if (!sourceMap.keySet().containsAll(expectedMaskedFieldsNames)) {
            mismatchDescription.appendValue("Document with id ").appendValue(response.getId())
                    .appendText(" does not contain all of expected masked fields. Actual fields: ").appendValue(sourceMap.keySet());
            return false;
        }
        for (String fieldName : sourceMap.keySet()) {
            boolean shouldBeMasked = expectedMaskedFieldsNames.contains(fieldName);
            if (shouldBeMasked && !expectedMaskValue.equals(sourceMap.get(fieldName))) {
                mismatchDescription.appendValue("Document with id ").appendValue(response.getId())
                        .appendText(" contains field with with name: ").appendText(fieldName)
                        .appendText(" that should be masked. Actual value: ").appendValue(sourceMap.get(fieldName));
                return false;
            }
            if (!shouldBeMasked && expectedMaskValue.equals(sourceMap.get(fieldName))) {
                mismatchDescription.appendValue("Actual search hit with docId: ").appendValue(response.getId())
                        .appendText(" contains field with with name: ").appendText(fieldName)
                        .appendText(" that should not be masked. Actual value: ").appendValue(sourceMap.get(fieldName));
                return false;
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Document contain exactly fields: ").appendValue(expectedMaskedFieldsNames)
                .appendText(" masked with: ").appendValue(expectedMaskValue);
    }
}
