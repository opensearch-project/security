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

import java.util.Arrays;
import java.util.List;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.indices.GetIndexResponse;

import static java.util.Objects.isNull;

class GetIndexResponseContainsIndicesMatcher extends TypeSafeDiagnosingMatcher<GetIndexResponse> {

    private final String[] expectedIndices;

    GetIndexResponseContainsIndicesMatcher(String[] expectedIndices) {
        if (isNull(expectedIndices) || 0 == expectedIndices.length) {
            throw new IllegalArgumentException("expectedIndices cannot be null or empty");
        }
        this.expectedIndices = expectedIndices;
    }

    @Override
    protected boolean matchesSafely(GetIndexResponse response, Description mismatchDescription) {
        List<String> actual = Arrays.asList(response.getIndices());
        for (String index : expectedIndices) {
            if (!actual.contains(index)) {
                mismatchDescription.appendText("Actual indices: ").appendValue(response.getIndices());
                return false;
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response should contain indices: ").appendValue(expectedIndices);
    }
}
