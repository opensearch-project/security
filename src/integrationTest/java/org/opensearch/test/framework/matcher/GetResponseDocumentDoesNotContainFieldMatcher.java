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

class GetResponseDocumentDoesNotContainFieldMatcher extends TypeSafeDiagnosingMatcher<GetResponse> {

    private final String fieldName;

    public GetResponseDocumentDoesNotContainFieldMatcher(String fieldName) {
        this.fieldName = requireNonNull(fieldName, "Field name is required.");
    }

    @Override
    protected boolean matchesSafely(GetResponse response, Description mismatchDescription) {
        Map<String, Object> source = response.getSource();
        if (source == null) {
            mismatchDescription.appendText("Source is not available in search results");
            return false;
        }
        if (source.containsKey(fieldName)) {
            mismatchDescription.appendText("Document contains field ").appendValue(fieldName);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Document does not contain field ").appendValue(fieldName);
    }
}
