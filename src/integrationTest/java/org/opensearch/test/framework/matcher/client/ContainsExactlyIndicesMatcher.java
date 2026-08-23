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

import java.util.HashSet;
import java.util.Set;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.core.FieldCapsResponse;

import static java.util.Objects.isNull;

class ContainsExactlyIndicesMatcher extends TypeSafeDiagnosingMatcher<FieldCapsResponse> {

    private final Set<String> expectedIndices;

    ContainsExactlyIndicesMatcher(String... expectedIndices) {
        if (isNull(expectedIndices) || expectedIndices.length == 0) {
            throw new IllegalArgumentException("expectedIndices cannot be null or empty");
        }
        this.expectedIndices = Set.of(expectedIndices);
    }

    @Override
    protected boolean matchesSafely(FieldCapsResponse response, Description mismatchDescription) {
        if (!expectedIndices.equals(new HashSet<>(response.indices()))) {
            mismatchDescription.appendText("Actual indices: ").appendValue(response.indices());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response contains indices: ").appendValue(expectedIndices);
    }
}
