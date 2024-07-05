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

package org.opensearch.security;

import com.google.common.collect.ImmutableMap;
import org.junit.Test;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class PrivilegesEvaluationTest extends SingleClusterTest {
    @Test
    public void resolveTestHidden() throws Exception {

        setup();

        try (Client client = getClient()) {

            client.index(
                new IndexRequest("hidden_test_not_hidden").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .source(XContentType.JSON, "index", "hidden_test_not_hidden", "b", "y", "date", "1985/01/01")
            ).actionGet();

            client.admin()
                .indices()
                .create(new CreateIndexRequest(".hidden_test_actually_hidden").settings(ImmutableMap.of("index.hidden", true)))
                .actionGet();
            client.index(
                new IndexRequest(".hidden_test_actually_hidden").id("test").source("a", "b").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            ).actionGet();
        }
        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse httpResponse = rh.executeGetRequest(
            "/*hidden_test*/_search?expand_wildcards=all&pretty=true",
            encodeBasicHeader("hidden_test", "nagilum")
        );
        assertThat(httpResponse.getBody(), httpResponse.getStatusCode(), is(403));

        httpResponse = rh.executeGetRequest("/hidden_test_not_hidden?pretty=true", encodeBasicHeader("hidden_test", "nagilum"));
        assertThat(httpResponse.getBody(), httpResponse.getStatusCode(), is(200));
    }
}
