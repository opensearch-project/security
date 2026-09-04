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

import org.hamcrest.Matcher;

import org.opensearch.client.opensearch.indices.ClearCacheResponse;
import org.opensearch.client.opensearch.indices.CloneIndexResponse;
import org.opensearch.client.opensearch.indices.CloseIndexResponse;
import org.opensearch.client.opensearch.indices.CreateIndexResponse;
import org.opensearch.client.opensearch.indices.GetIndexResponse;
import org.opensearch.client.opensearch.indices.GetIndicesSettingsResponse;
import org.opensearch.client.opensearch.indices.GetMappingResponse;
import org.opensearch.client.opensearch.indices.OpenResponse;
import org.opensearch.client.opensearch.indices.ShrinkResponse;
import org.opensearch.client.opensearch.indices.SplitResponse;

public class IndexResponseMatchers {

    public static Matcher<CreateIndexResponse> isSuccessfulCreateIndexResponse(String expectedIndexName) {
        return new SuccessfulCreateIndexResponseMatcher(expectedIndexName);
    }

    public static Matcher<GetIndexResponse> getIndexResponseContainsIndices(String... expectedIndices) {
        return new GetIndexResponseContainsIndicesMatcher(expectedIndices);
    }

    public static Matcher<CloseIndexResponse> isSuccessfulCloseIndexResponse() {
        return new SuccessfulCloseIndexResponseMatcher();
    }

    public static Matcher<OpenResponse> isSuccessfulOpenIndexResponse() {
        return new SuccessfulOpenIndexResponseMatcher();
    }

    public static Matcher<ShrinkResponse> isSuccessfulResizeResponse(String expectedIndexName) {
        return new SuccessfulResizeResponseMatcher(expectedIndexName);
    }

    public static Matcher<CloneIndexResponse> isSuccessfulCloneResponse(String expectedIndexName) {
        return new SuccessfulCloneResponseMatcher(expectedIndexName);
    }

    public static Matcher<SplitResponse> isSuccessfulSplitResponse(String expectedIndexName) {
        return new SuccessfulSplitResponseMatcher(expectedIndexName);
    }

    public static Matcher<GetIndicesSettingsResponse> getSettingsResponseContainsIndices(String... expectedIndices) {
        return new GetSettingsResponseContainsIndicesMatcher(expectedIndices);
    }

    public static Matcher<ClearCacheResponse> isSuccessfulClearIndicesCacheResponse() {
        return new SuccessfulClearIndicesCacheResponseMatcher();
    }

    public static Matcher<GetMappingResponse> getMappingsResponseContainsIndices(String... expectedIndices) {
        return new GetMappingsResponseContainsIndicesMatcher(expectedIndices);
    }

}
