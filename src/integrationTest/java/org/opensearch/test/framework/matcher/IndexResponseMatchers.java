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

import org.opensearch.action.admin.indices.cache.clear.ClearIndicesCacheResponse;
import org.opensearch.action.admin.indices.open.OpenIndexResponse;
import org.opensearch.action.admin.indices.settings.get.GetSettingsResponse;
import org.opensearch.client.indices.CloseIndexResponse;
import org.opensearch.client.indices.CreateIndexResponse;
import org.opensearch.client.indices.GetIndexResponse;
import org.opensearch.client.indices.GetMappingsResponse;
import org.opensearch.client.indices.ResizeResponse;

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

    public static Matcher<OpenIndexResponse> isSuccessfulOpenIndexResponse() {
        return new SuccessfulOpenIndexResponseMatcher();
    }

    public static Matcher<ResizeResponse> isSuccessfulResizeResponse(String expectedIndexName) {
        return new SuccessfulResizeResponseMatcher(expectedIndexName);
    }

    public static Matcher<GetSettingsResponse> getSettingsResponseContainsIndices(String... expectedIndices) {
        return new GetSettingsResponseContainsIndicesMatcher(expectedIndices);
    }

    public static Matcher<ClearIndicesCacheResponse> isSuccessfulClearIndicesCacheResponse() {
        return new SuccessfulClearIndicesCacheResponseMatcher();
    }

    public static Matcher<GetMappingsResponse> getMappingsResponseContainsIndices(String... expectedIndices) {
        return new GetMappingsResponseContainsIndicesMatcher(expectedIndices);
    }

}
