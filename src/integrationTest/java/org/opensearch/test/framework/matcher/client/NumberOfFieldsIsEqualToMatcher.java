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

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.core.FieldCapsResponse;

class NumberOfFieldsIsEqualToMatcher extends TypeSafeDiagnosingMatcher<FieldCapsResponse> {

    private final int expectedNumberOfFields;

    NumberOfFieldsIsEqualToMatcher(int expectedNumberOfFields) {
        this.expectedNumberOfFields = expectedNumberOfFields;
    }

    @Override
    protected boolean matchesSafely(FieldCapsResponse response, Description mismatchDescription) {
        if (expectedNumberOfFields != response.fields().size()) {
            mismatchDescription.appendText("Actual number of fields: ").appendValue(response.fields().size());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response contains information about ").appendValue(expectedNumberOfFields).appendText(" fields");
    }
}
