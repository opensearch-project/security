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

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.get.GetResponse;

import static java.util.Objects.isNull;

class GetResponseDocumentContainsExactlyFieldsWithNamesMatcher extends TypeSafeDiagnosingMatcher<GetResponse> {

    private final Set<String> expectedFieldsNames;

    GetResponseDocumentContainsExactlyFieldsWithNamesMatcher(String... expectedFieldsNames) {
        if (isNull(expectedFieldsNames) || expectedFieldsNames.length == 0) {
            throw new IllegalArgumentException("expectedFieldsNames cannot be null or empty");
        }
        this.expectedFieldsNames = Set.of(expectedFieldsNames);
    }

    @Override
    protected boolean matchesSafely(GetResponse response, Description mismatchDescription) {
        Map<String, Object> sourceMap = response.getSourceAsMap();
        Set<String> actualFieldsNames = sourceMap.keySet();
        if (!expectedFieldsNames.equals(actualFieldsNames)) {
            mismatchDescription.appendValue("Document with id ")
                .appendValue(response.getId())
                .appendText(" contains fields with names: ")
                .appendValue(actualFieldsNames);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Document contain exactly fields with names: ").appendValue(expectedFieldsNames);
    }
}
