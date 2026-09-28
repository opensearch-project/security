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

import org.opensearch.client.opensearch.core.get.GetResult;

import static java.util.Objects.requireNonNull;

class GetResultContainOnlyDocumentIdMatcher extends TypeSafeDiagnosingMatcher<GetResult<?>> {

    private final String indexName;
    private final String documentId;

    public GetResultContainOnlyDocumentIdMatcher(String indexName, String documentId) {
        this.indexName = requireNonNull(indexName, "Index name is required");
        this.documentId = requireNonNull(documentId, "Document id is required");
    }

    @Override
    protected boolean matchesSafely(GetResult<?> response, Description mismatchDescription) {
        if (indexName.equals(response.index()) == false) {
            mismatchDescription.appendText(" index name ").appendValue(response.index()).appendText(" is incorrect ");
            return false;
        }
        if (documentId.equals(response.id()) == false) {
            mismatchDescription.appendText(" id ").appendValue(response.id()).appendText(" is incorrect ");
            return false;
        }
        if (response.found()) {
            mismatchDescription.appendText(" document exist what is not desired ");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response should contain document id from index ")
            .appendValue(indexName)
            .appendText(" with id ")
            .appendValue(documentId)
            .appendText(" but document should not be present ");
    }
}
