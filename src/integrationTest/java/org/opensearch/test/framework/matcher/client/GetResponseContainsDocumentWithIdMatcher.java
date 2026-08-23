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

import org.opensearch.client.opensearch.core.GetResponse;

import static java.util.Objects.requireNonNull;

class GetResponseContainsDocumentWithIdMatcher extends TypeSafeDiagnosingMatcher<GetResponse<?>> {

    private final String indexName;
    private final String documentId;

    public GetResponseContainsDocumentWithIdMatcher(String indexName, String documentId) {
        this.indexName = requireNonNull(indexName, "Index name is required");
        this.documentId = requireNonNull(documentId, "Document id is required");
    }

    @Override
    protected boolean matchesSafely(GetResponse<?> response, Description mismatchDescription) {
        if (indexName.equals(response.index()) == false) {
            mismatchDescription.appendText("Document should not belong to index ").appendValue(response.index());
            return false;
        }
        if (documentId.equals(response.id()) == false) {
            mismatchDescription.appendText("Document contain incorrect id which is ").appendValue(response.id());
            return false;
        }
        if (response.found() == false) {
            mismatchDescription.appendText("Document does not exist or is inaccessible");
            return false;
        }
        if (response.source() == null) {
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
