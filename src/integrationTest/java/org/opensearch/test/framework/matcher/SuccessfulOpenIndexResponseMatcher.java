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

import org.opensearch.action.admin.indices.open.OpenIndexResponse;

class SuccessfulOpenIndexResponseMatcher extends TypeSafeDiagnosingMatcher<OpenIndexResponse> {

    @Override
    protected boolean matchesSafely(OpenIndexResponse response, Description mismatchDescription) {
        if (!response.isShardsAcknowledged()) {
            mismatchDescription.appendText("shardsAcknowledged is equal to ").appendValue(response.isShardsAcknowledged());
            return false;
        }
        if (!response.isAcknowledged()) {
            mismatchDescription.appendText("acknowledged is equal to ").appendValue(response.isShardsAcknowledged());
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful open index response");
    }
}
