/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard;

import static org.elasticsearch.test.ESIntegTestCase.Scope.SUITE;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collection;

import org.elasticsearch.action.WriteConsistencyLevel;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.BoundTransportAddress;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.ESIntegTestCase.ClusterScope;
import org.junit.Ignore;
import org.junit.Test;

import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin;
import com.floragunn.searchguard.support.Base64Helper;

//@ClusterScope(scope = SUITE, transportClientRatio = 1, numDataNodes = 3, numClientNodes = 0)
@Ignore
public class SearchGuardTests extends ESIntegTestCase {

    @Override
    protected Settings transportClientSettings() {
        final Settings.Builder settings = Settings.builder().put(super.transportClientSettings())
                .put("path.conf", "/Users/temp/search-guard2/src/test/resources")
                .put("searchguard.ssl.transport.keystore_filepath", "kirk-keystore.jks")
                .put("searchguard.ssl.transport.truststore_filepath", "truststore.jks")
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).put("searchguard.ssl.transport.enabled", true);
        return settings.build();
    }

    @Override
    protected Collection<Class<? extends Plugin>> transportClientPlugins() {
        return pluginList(SearchGuardSSLPlugin.class, SearchGuardPlugin.class);
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return pluginList(SearchGuardSSLPlugin.class, SearchGuardPlugin.class);
    }

    @Override
    protected Settings nodeSettings(final int nodeOrdinal) {
        final Settings.Builder settings = Settings
                .builder()
                .put(super.nodeSettings(nodeOrdinal))
                .put("index.number_of_shards", 1)
                // searchguard index must only be one shard ever
                .put("index.number_of_replicas", 3)
                .put("path.conf", "/Users/temp/search-guard2/src/test/resources")
                .put("searchguard.ssl.transport.keystore_filepath", "node-0-keystore.jks")
                .put("searchguard.ssl.transport.truststore_filepath", "truststore.jks")
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .put("searchguard.ssl.transport.enabled", true)
                .put("http.enabled", true)

                .putArray("searchguard.authcz.admin_dn", "cn=xxx,ou=ccc,ou=qqqr,dc=wwwe,dc=de",
                        "CN=kirk,OU=client,   O=client,l=tEst, C=De");
        return settings.build();
    }

    @Test
    public void testHttp() throws Exception {

        Thread.sleep(2000);

        init(client(), "sg_config.yml", "config");
        init(client(), "sg_roles.yml", "roles");
        init(client(), "sg_roles_mapping.yml", "rolesmapping");
        init(client(), "sg_internal_users.yml", "internalusers");
        init(client(), "sg_action_groups.yml", "actiongroups");

        Thread.sleep(2000);

        final Settings.Builder settings = Settings.builder()

                .put("cluster.name", cluster().getClusterName()).put("path.home", ".").put("node.data", false).put("node.local", true)
                .put("path.conf", "/Users/temp/search-guard2/src/test/resources")
                .put("searchguard.ssl.transport.keystore_filepath", "spock-keystore.jks")
                .put("searchguard.ssl.transport.truststore_filepath", "truststore.jks")
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).put("searchguard.ssl.transport.enabled", true);

        final Node n = new PluginAwareNode(settings.build(), SearchGuardSSLPlugin.class, SearchGuardPlugin.class).start();

        Thread.sleep(12000);

        final BoundTransportAddress ta = client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes()[0].getHttp()
                .address();

        final HttpURLConnection connection = (HttpURLConnection) new URL("http://" + ta.publishAddress().getHost() + ":"
                + ta.publishAddress().getPort() + "/_search").openConnection();
        final String encoded = Base64Helper.encodeBasicHeader("kirk", "testabc");
        connection.setRequestProperty("Authorization", "Basic " + encoded);
        connection.connect();
        n.close();
        System.out.println(connection.getResponseCode());
        System.out.println(connection.getResponseMessage());
        // System.out.println(IOUtils.toString(connection.getInputStream()));

    }

    @Test
    public void test() {
        final Settings.Builder settings = Settings.builder().put(super.transportClientSettings())
                .put("cluster.name", cluster().getClusterName()).put("path.home", ".")
                .put("path.conf", "/Users/temp/search-guard2/src/test/resources")
                .put("searchguard.ssl.transport.keystore_filepath", "spock-keystore.jks")
                .put("searchguard.ssl.transport.truststore_filepath", "truststore.jks")
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).put("searchguard.ssl.transport.enabled", true);

        System.out.println("-------------------  init");

        final TransportClient tc = TransportClient.builder().settings(settings.build()).addPlugin(SearchGuardPlugin.class)
                .addPlugin(SearchGuardSSLPlugin.class).build();

        final TransportAddress ta = client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes()[0].getNode()
                .address();

        tc.addTransportAddress(ta);

        System.out.println("-------------------  exec " + ta);

        System.out.println(tc.index(new IndexRequest("truut").type("t1").source("{}")).actionGet().getId());
    }

    protected void init(final Client client, final String file, final String type) throws Exception {
        try (Reader reader = new FileReader(file)) {

            try {
                client.admin().indices()
                .create(new CreateIndexRequest("searchguard").settings("index.number_of_shards", 1, "index.number_of_replicas", 2))
                .actionGet();
            } catch (final Exception e) {

            }

            final String id = client
                    .index(new IndexRequest("searchguard").type(type).id("0").refresh(true).consistencyLevel(WriteConsistencyLevel.DEFAULT)
                            .source(readXContent(reader, XContentType.YAML))).actionGet().getId();

            if ("0".equals(id)) {
                System.out.println(type + " created or updated");
            } else {
                System.out.println("failed");
                return;// System.exit(-1);
            }

        }
    }

    private static BytesReference readXContent(final Reader reader, final XContentType xContentType) throws IOException {
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(reader);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            return builder.bytes();
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
    }
}
