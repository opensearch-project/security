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

import org.opensearch.client.indices.CreateIndexResponse;

import static java.util.Objects.requireNonNull;

class SuccessfulCreateIndexResponseMatcher extends TypeSafeDiagnosingMatcher<CreateIndexResponse> {

    private final String expectedIndexName;

    SuccessfulCreateIndexResponseMatcher(String expectedIndexName) {
        this.expectedIndexName = requireNonNull(expectedIndexName);
    }

    @Override
    protected boolean matchesSafely(CreateIndexResponse response, Description mismatchDescription) {
        if (!expectedIndexName.equals(response.index())) {
            mismatchDescription.appendText("Index name ")
                .appendValue(response.index())
                .appendText(" does not match expected index name ")
                .appendValue(expectedIndexName);
            return false;
        }
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
        description.appendText("Successful create index response");
    }
}
