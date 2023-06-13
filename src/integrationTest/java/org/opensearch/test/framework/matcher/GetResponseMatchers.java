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

import org.hamcrest.Matcher;

import org.opensearch.action.get.GetResponse;

public class GetResponseMatchers {

    private GetResponseMatchers() {}

    public static Matcher<GetResponse> containDocument(String indexName, String documentId) {
        return new GetResponseContainsDocumentWithIdMatcher(indexName, documentId);
    }

    public static Matcher<GetResponse> containOnlyDocumentId(String indexName, String documentId) {
        return new GetResponseContainOnlyDocumentIdMatcher(indexName, documentId);
    }

    public static Matcher<GetResponse> documentContainField(String fieldName, Object fieldValue) {
        return new GetResponseDocumentFieldValueMatcher(fieldName, fieldValue);
    }

    public static Matcher<GetResponse> documentDoesNotContainField(String fieldName) {
        return new GetResponseDocumentDoesNotContainFieldMatcher(fieldName);
    }

    public static Matcher<GetResponse> documentContainsExactlyFieldsWithNames(String... expectedFieldsNames) {
        return new GetResponseDocumentContainsExactlyFieldsWithNamesMatcher(expectedFieldsNames);
    }
}
