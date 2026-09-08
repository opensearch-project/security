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

import org.opensearch.client.opensearch.core.mget.MultiGetResponseItem;

import static java.util.Objects.requireNonNull;

class MultiGetResponseItemContainsDocumentWithIdMatcher extends TypeSafeDiagnosingMatcher<MultiGetResponseItem<?>> {

    private final String indexName;
    private final String documentId;

    public MultiGetResponseItemContainsDocumentWithIdMatcher(String indexName, String documentId) {
        this.indexName = requireNonNull(indexName, "Index name is required");
        this.documentId = requireNonNull(documentId, "Document id is required");
    }

    @Override
    protected boolean matchesSafely(MultiGetResponseItem<?> response, Description mismatchDescription) {
        if (indexName.equals(response.result().index()) == false) {
            mismatchDescription.appendText("Document should not belong to index ").appendValue(response.result().index());
            return false;
        }
        if (documentId.equals(response.result().id()) == false) {
            mismatchDescription.appendText("Document contain incorrect id which is ").appendValue(response.result().id());
            return false;
        }
        if (response.result().found() == false) {
            mismatchDescription.appendText("Document does not exist or is inaccessible");
            return false;
        }
        if (response.result().source() == null) {
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
