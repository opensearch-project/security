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

import org.opensearch.action.get.GetResponse;

import static java.util.Objects.requireNonNull;

class GetResponseContainsDocumentWithIdMatcher extends TypeSafeDiagnosingMatcher<GetResponse> {

    private final String indexName;
    private final String documentId;

    public GetResponseContainsDocumentWithIdMatcher(String indexName, String documentId) {
        this.indexName = requireNonNull(indexName, "Index name is required");
        this.documentId = requireNonNull(documentId, "Document id is required");
    }

    @Override
    protected boolean matchesSafely(GetResponse response, Description mismatchDescription) {
        if (indexName.equals(response.getIndex()) == false) {
            mismatchDescription.appendText("Document should not belong to index ").appendValue(response.getIndex());
            return false;
        }
        if (documentId.equals(response.getId()) == false) {
            mismatchDescription.appendText("Document contain incorrect id which is ").appendValue(response.getId());
            return false;
        }
        if (response.isExists() == false) {
            mismatchDescription.appendText("Document does not exist or is inaccessible");
            return false;
        }
        if (response.isSourceEmpty()) {
            mismatchDescription.appendText("Document source is empty");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response should contain document from index ")
            .appendValue(indexName)
            .appendText(" with id ")
            .appendValue(documentId);
    }
}
