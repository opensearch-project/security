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

import org.opensearch.action.search.DeletePitInfo;
import org.opensearch.action.search.DeletePitResponse;
import org.opensearch.core.rest.RestStatus;

class SuccessfulDeletePitResponseMatcher extends TypeSafeDiagnosingMatcher<DeletePitResponse> {

    @Override
    protected boolean matchesSafely(DeletePitResponse response, Description mismatchDescription) {
        if (!RestStatus.OK.equals(response.status())) {
            mismatchDescription.appendText("has status ").appendValue(response.status()).appendText(" which denotes failure.");
            return false;
        }
        for (DeletePitInfo deletePitInfo : response.getDeletePitResults()) {
            if (!deletePitInfo.isSuccessful()) {
                mismatchDescription.appendValue("Pit: ")
                    .appendValue(deletePitInfo.getPitId())
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
