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

import org.opensearch.client.opensearch.core.get.GetResult;

import static java.util.Objects.requireNonNull;

class GetResultDocumentFieldValueMatcher extends TypeSafeDiagnosingMatcher<GetResult<?>> {

    private final String fieldName;
    private final Object fieldValue;

    public GetResultDocumentFieldValueMatcher(String fieldName, Object fieldValue) {
        this.fieldName = requireNonNull(fieldName, "Field name is required.");
        this.fieldValue = requireNonNull(fieldValue, "Field value is required.");
    }

    @Override
    protected boolean matchesSafely(GetResult<?> response, Description mismatchDescription) {
        Map<String, Object> source = (Map<String, Object>) response.source();
        if (source == null) {
            mismatchDescription.appendText("Source is not available in search results");
            return false;
        }
        if (source.containsKey(fieldName) == false) {
            mismatchDescription.appendText("Document does not contain field ").appendValue(fieldName);
            return false;
        }
        Object actualFieldValue = source.get(fieldName);
        if (fieldValue.equals(actualFieldValue) == false) {
            mismatchDescription.appendText("Field ")
                .appendValue(fieldName)
                .appendText(" has incorrect value ")
                .appendValue(actualFieldValue);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Document contain field ").appendValue(fieldName).appendText(" with value ").appendValue(fieldValue);
    }
}
