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

import org.opensearch.client.opensearch.core.UpdateResponse;

class SuccessfulUpdateResponseMatcher extends TypeSafeDiagnosingMatcher<UpdateResponse<?>> {

    @Override
    protected boolean matchesSafely(UpdateResponse<?> response, Description mismatchDescription) {
        if (response.shards().failed() != 0) {
            mismatchDescription.appendText("contains ").appendValue(response.shards().failed()).appendText(" shard failures");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful update response");
    }
}
