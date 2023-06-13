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

import java.util.concurrent.ExecutionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.client.Client;

import static java.util.Objects.requireNonNull;

class ClusterContainsDocumentMatcher extends TypeSafeDiagnosingMatcher<Client> {

    private static final Logger log = LogManager.getLogger(ClusterContainsDocumentMatcher.class);

    private final String indexName;
    private final String documentId;

    ClusterContainsDocumentMatcher(String indexName, String documentId) {
        this.indexName = requireNonNull(indexName, "Index name is required.");
        this.documentId = requireNonNull(documentId, "Document id is required.");
    }

    @Override
    protected boolean matchesSafely(Client client, Description mismatchDescription) {
        try {
            GetResponse response = client.get(new GetRequest(indexName, documentId)).get();
            if (response.isExists() == false) {
                mismatchDescription.appendText("Document does not exists");
                return false;
            }
        } catch (InterruptedException | ExecutionException e) {
            log.error("Cannot verify if cluster contains document '{}' in index '{}'.", documentId, indexName, e);
            mismatchDescription.appendText("Exception occured during verification if cluster contain document").appendValue(e);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Cluster contain document in index ").appendValue(indexName).appendText(" with id ").appendValue(documentId);
    }
}
