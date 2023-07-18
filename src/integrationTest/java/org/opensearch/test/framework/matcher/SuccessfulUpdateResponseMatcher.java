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

import org.opensearch.action.update.UpdateResponse;
import org.opensearch.core.rest.RestStatus;

class SuccessfulUpdateResponseMatcher extends TypeSafeDiagnosingMatcher<UpdateResponse> {

    @Override
    protected boolean matchesSafely(UpdateResponse response, Description mismatchDescription) {
        if (!RestStatus.OK.equals(response.status())) {
            mismatchDescription.appendText("has status ").appendValue(response.status()).appendText(" which denotes failure.");
            return false;
        }
        if (response.getShardInfo().getFailures().length != 0) {
            mismatchDescription.appendText("contains ")
                .appendValue(response.getShardInfo().getFailures().length)
                .appendText(" shard failures");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful update response");
    }
}
