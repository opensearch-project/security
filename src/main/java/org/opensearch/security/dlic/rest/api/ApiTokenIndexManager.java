/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.support.ConfigConstants;

public class ApiTokenIndexManager {

    private Client client;

    public ApiTokenIndexManager(Client client) {
        this.client = client;
    }

    public void indexToken(ApiToken token) {
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {

            XContentBuilder builder = XContentFactory.jsonBuilder();
            String jsonString = token.toXContent(builder, ToXContent.EMPTY_PARAMS).toString();

            IndexRequest request = new IndexRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX) // Index name
                .source(jsonString, XContentType.JSON); // Set JSON source

            client.index(request);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public Object getTokens() {
        try (final ThreadContext.StoredContext ctx = client.threadPool().getThreadContext().stashContext()) {

            return client.get(new GetRequest(ConfigConstants.OPENSEARCH_API_TOKENS_INDEX));

        }
    }

}
