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

import org.opensearch.action.get.GetResponse;

import static java.util.Objects.requireNonNull;

class GetResponseDocumentFieldValueMatcher extends TypeSafeDiagnosingMatcher<GetResponse> {

    private final String fieldName;
    private final Object fieldValue;

    public GetResponseDocumentFieldValueMatcher(String fieldName, Object fieldValue) {
        this.fieldName = requireNonNull(fieldName, "Field name is required.");
        this.fieldValue = requireNonNull(fieldValue, "Field value is required.");
    }

    @Override
    protected boolean matchesSafely(GetResponse response, Description mismatchDescription) {
        Map<String, Object> source = response.getSource();
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
