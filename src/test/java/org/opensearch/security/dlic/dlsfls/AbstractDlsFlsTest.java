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

package org.opensearch.security.dlic.dlsfls;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public abstract class AbstractDlsFlsTest extends SingleClusterTest {

    protected RestHelper rh = null;

    @Override
    protected String getResourceFolder() {
        return "dlsfls";
    }

    protected final void setup() throws Exception {
        setup(Settings.EMPTY);
    }

    protected final void setup(Settings override) throws Exception {
        setup(override, new DynamicSecurityConfig(), ClusterConfiguration.DEFAULT);
    }

    protected final void setup(DynamicSecurityConfig dynamicSecurityConfig) throws Exception {
        setup(Settings.EMPTY, dynamicSecurityConfig, ClusterConfiguration.DEFAULT);
    }

    protected final void setup(Settings override, DynamicSecurityConfig dynamicSecurityConfig) throws Exception {
        setup(override, dynamicSecurityConfig, ClusterConfiguration.DEFAULT);
    }

    protected final void setup(DynamicSecurityConfig dynamicSecurityConfig, ClusterConfiguration clusterConfiguration) throws Exception {
        setup(Settings.EMPTY, dynamicSecurityConfig, clusterConfiguration);
    }

    protected final void setup(Settings override, DynamicSecurityConfig dynamicSecurityConfig, ClusterConfiguration clusterConfiguration)
        throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, "debug").put(override).build();
        setup(Settings.EMPTY, dynamicSecurityConfig, settings, true, clusterConfiguration);

        try (Client tc = getClient()) {
            populateData(tc);
        }

        rh = nonSslRestHelper();
    }

    protected SearchResponse executeSearch(String indexName, String user, String password) throws Exception {
        HttpResponse response = rh.executeGetRequest("/" + indexName + "/_search?from=0&size=50&pretty", encodeBasicHeader(user, password));
        assertThat(response.getStatusCode(), is(200));
        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        return SearchResponse.fromXContent(xcp);
    }

    protected GetResponse executeGet(String indexName, String id, String user, String password) throws Exception {
        HttpResponse response = rh.executeGetRequest("/" + indexName + "/_doc/" + id, encodeBasicHeader(user, password));
        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        return GetResponse.fromXContent(xcp);
    }

    protected MultiSearchResponse executeMSearchMatchAll(String user, String password, String... indexName) throws Exception {
        StringBuilder body = new StringBuilder();

        for (String index : indexName) {
            body.append("{\"index\": \"").append(index).append("\"}\n");
            body.append("{\"query\" : {\"match_all\" : {}}}\n");
        }

        HttpResponse response = rh.executePostRequest("/_msearch?pretty", body.toString(), encodeBasicHeader(user, password));
        assertThat(response.getStatusCode(), is(200));
        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        return MultiSearchResponse.fromXContext(xcp);
    }

    protected MultiGetResponse executeMGet(String user, String password, Map<String, String> indicesAndIds) throws Exception {

        Set<String> indexAndIdJson = new HashSet<>();
        for (Map.Entry<String, String> indexAndId : indicesAndIds.entrySet()) {
            indexAndIdJson.add("{ \"_index\": \"" + indexAndId.getKey() + "\", \"_id\": \"" + indexAndId.getValue() + "\" }");
        }
        String body = "{ \"docs\": [" + String.join(",", indexAndIdJson) + "] }";

        HttpResponse response = rh.executePostRequest("/_mget?pretty", body, encodeBasicHeader(user, password));
        assertThat(response.getStatusCode(), is(200));
        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        return MultiGetResponse.fromXContent(xcp);
    }

    abstract void populateData(Client tc);

}
