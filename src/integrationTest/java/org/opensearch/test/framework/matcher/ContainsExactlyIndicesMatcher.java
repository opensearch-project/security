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

import java.util.Set;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.fieldcaps.FieldCapabilitiesResponse;

import static java.util.Objects.isNull;

class ContainsExactlyIndicesMatcher extends TypeSafeDiagnosingMatcher<FieldCapabilitiesResponse> {

    private final Set<String> expectedIndices;

    ContainsExactlyIndicesMatcher(String... expectedIndices) {
        if (isNull(expectedIndices) || expectedIndices.length == 0) {
            throw new IllegalArgumentException("expectedIndices cannot be null or empty");
        }
        this.expectedIndices = Set.of(expectedIndices);
    }

    @Override
    protected boolean matchesSafely(FieldCapabilitiesResponse response, Description mismatchDescription) {
        Set<String> actualIndices = Set.of(response.getIndices());
        if (!expectedIndices.equals(actualIndices)) {
            mismatchDescription.appendText("Actual indices: ").appendValue(actualIndices);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response contains indices: ").appendValue(expectedIndices);
    }
}
