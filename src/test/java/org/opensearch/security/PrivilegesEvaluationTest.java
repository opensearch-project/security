package org.opensearch.security;

import org.junit.Assert;
import org.junit.Test;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

import com.google.common.collect.ImmutableMap;

public class PrivilegesEvaluationTest extends SingleClusterTest {
    @Test
    public void resolveTestHidden() throws Exception {

        setup();

        try (Client client = getInternalTransportClient()) {

            client.index(new IndexRequest("hidden_test_not_hidden").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(XContentType.JSON, "index",
                    "hidden_test_not_hidden", "b", "y", "date", "1985/01/01")).actionGet();

            client.admin().indices().create(new CreateIndexRequest(".hidden_test_actually_hidden").settings(ImmutableMap.of("index.hidden", true)))
                                       .actionGet();
            client.index(new IndexRequest(".hidden_test_actually_hidden").id("test").source("a", "b").setRefreshPolicy(RefreshPolicy.IMMEDIATE))
                    .actionGet();
        }
        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse httpResponse = rh.executeGetRequest("/*hidden_test*/_search?expand_wildcards=all&pretty=true",
                encodeBasicHeader("hidden_test", "nagilum"));
        Assert.assertEquals(httpResponse.getBody(), 403, httpResponse.getStatusCode());

        httpResponse = rh.executeGetRequest("/hidden_test_not_hidden?pretty=true",
                encodeBasicHeader("hidden_test", "nagilum"));
        Assert.assertEquals(httpResponse.getBody(), 200, httpResponse.getStatusCode());
    }
}
