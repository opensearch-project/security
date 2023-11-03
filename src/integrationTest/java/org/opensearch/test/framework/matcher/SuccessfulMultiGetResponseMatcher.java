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

import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetResponse;

class SuccessfulMultiGetResponseMatcher extends TypeSafeDiagnosingMatcher<MultiGetResponse> {

    @Override
    protected boolean matchesSafely(MultiGetResponse response, Description mismatchDescription) {
        for (MultiGetItemResponse getItemResponse : response.getResponses()) {
            if (getItemResponse.isFailed()) {
                mismatchDescription.appendValue("Get an item from index: ")
                    .appendValue(getItemResponse.getIndex())
                    .appendText(" failed: ")
                    .appendValue(getItemResponse.getFailure().getMessage());
                return false;
            }
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful multi get response");
    }
}
