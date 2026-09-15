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

import org.opensearch.client.opensearch.indices.OpenResponse;

class SuccessfulOpenIndexResponseMatcher extends TypeSafeDiagnosingMatcher<OpenResponse> {

    @Override
    protected boolean matchesSafely(OpenResponse response, Description mismatchDescription) {
        if (!response.shardsAcknowledged()) {
            mismatchDescription.appendText("shardsAcknowledged is equal to ").appendValue(response.shardsAcknowledged());
            return false;
        }
        if (!response.acknowledged()) {
            mismatchDescription.appendText("acknowledged is equal to ").appendValue(response.acknowledged());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful open index response");
    }
}
