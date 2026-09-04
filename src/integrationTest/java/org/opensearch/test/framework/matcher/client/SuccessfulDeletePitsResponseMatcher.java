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

import org.opensearch.client.opensearch.core.DeleteAllPitsResponse;
import org.opensearch.client.opensearch.core.pit.DeletedPit;

class SuccessfulDeletePitsResponseMatcher extends TypeSafeDiagnosingMatcher<DeleteAllPitsResponse> {

    @Override
    protected boolean matchesSafely(DeleteAllPitsResponse response, Description mismatchDescription) {
        for (DeletedPit deletePitInfo : response.pits()) {
            if (!deletePitInfo.successful()) {
                mismatchDescription.appendValue("Pit: ")
                    .appendValue(deletePitInfo.pitId())
                    .appendText(" - delete result was not successful");
                return false;
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful delete pit response");
    }
}
