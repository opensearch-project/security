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

import org.opensearch.client.opensearch.core.MgetResponse;
import org.opensearch.client.opensearch.core.mget.MultiGetResponseItem;

class SuccessfulMultiGetResponseMatcher extends TypeSafeDiagnosingMatcher<MgetResponse<?>> {

    @Override
    protected boolean matchesSafely(MgetResponse<?> response, Description mismatchDescription) {
        for (MultiGetResponseItem<?> getItemResponse : response.docs()) {
            if (getItemResponse.isFailure()) {
                mismatchDescription.appendValue("Get an item from index: ")
                    .appendValue(getItemResponse.failure().index())
                    .appendText(" failed: ")
                    .appendValue(getItemResponse.failure().error().reason());
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
