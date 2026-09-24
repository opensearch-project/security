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

import org.opensearch.client.opensearch.core.MsearchResponse;
import org.opensearch.client.opensearch.core.msearch.MultiSearchResponseItem;

class SuccessfulMultiSearchResponseMatcher extends TypeSafeDiagnosingMatcher<MsearchResponse<?>> {

    @Override
    protected boolean matchesSafely(MsearchResponse<?> response, Description mismatchDescription) {
        for (MultiSearchResponseItem<?> itemResponse : response.responses()) {
            if (itemResponse.isFailure()) {
                mismatchDescription.appendValue("Get an item failed: ").appendValue(itemResponse.failure().error().reason());
                return false;
            }
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful multi search response");
    }
}
