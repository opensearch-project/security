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

package com.floragunn.searchguard.tools;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.net.InetSocketAddress;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.elasticsearch.action.WriteConsistencyLevel;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.ssl.SearchGuardSSLPlugin;

public class SearchGuardAdmin {

    public static void main(final String[] args) throws Exception {

        final HelpFormatter formatter = new HelpFormatter();
        Options options = new Options();
        options.addOption( "nhnv", "disable-host-name-verification", false, "Disable hostname verification" );
        options.addOption( "nrhn", "disable-resolve-hostname", false, "Disable hostname beeing resolved" );
        options.addOption(Option.builder("ts").longOpt("truststore").hasArg().argName("file").required().desc("Path to truststore (in JKS format").build());
        options.addOption(Option.builder("ks").longOpt("keystore").hasArg().argName("file").required().desc("Path to keystore (in JKS format").build());
        options.addOption(Option.builder("tspass").longOpt("truststore-password").hasArg().argName("password").desc("Truststore password").build());
        options.addOption(Option.builder("kspass").longOpt("keystore-password").hasArg().argName("password").desc("Keystore password").build());
        options.addOption(Option.builder("cd").longOpt("configdir").hasArg().argName("directory").desc("Directory for config files").build());
        options.addOption(Option.builder("h").longOpt("hostname").hasArg().argName("host").desc("Elasticsearch host").build());
        options.addOption(Option.builder("p").longOpt("port").hasArg().argName("port").desc("Elasticsearch port").build());
        
        
        String hostname = "localhost";
        int port = 9300;
        String kspass = "changeit";
        String tspass = kspass;
        String cd = ".";
        String ks;
        String ts;
        boolean nhnv = false;
        boolean nrhn = false;
        
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse( options, args );
            hostname = line.getOptionValue("h", hostname);
            port = Integer.parseInt(line.getOptionValue("p", String.valueOf(port)));
            kspass = line.getOptionValue("kspass", kspass);
            tspass = line.getOptionValue("tspass", tspass);
            cd = line.getOptionValue("cd", cd);
            ks = line.getOptionValue("ks");
            ts = line.getOptionValue("ts");
            nhnv = line.hasOption("nhnv");
            nrhn = line.hasOption("nrhn");
        }
        catch( ParseException exp ) {
            System.err.println("Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("sgadmin.sh", options, true);
            return;
        }
        
        
        System.out.println("Connect to "+hostname+":"+port);

        /*final Settings nsettings = Settings
                .builder()
                .put("path.home", ".")
                // .putArray("plugin.types", SearchGuardPlugin.class.getName(),
                // SearchGuardSSLPlugin.class.getName())
                .put("index.number_of_shards", "1")
                .put("index.number_of_replicas", "0")
                .put("path.conf", "/Users/temp/search-guard2/src/test/resources")
                .put("searchguard.ssl.transport.keystore_filepath", "node-0-keystore.jks")
                .put("searchguard.ssl.transport.truststore_filepath", "truststore.jks")
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)
                .put("searchguard.ssl.transport.enabled", true)

                .putArray("searchguard.authcz.admin_dn", "cn=xxx,ou=ccc,ou=qqqr,dc=wwwe,dc=de",
                        "CN=kirk,OU=client,   O=client,l=tEst, C=De")

                .build();*/

        //new PluginAwareNode(nsettings, SearchGuardSSLPlugin.class, SearchGuardPlugin.class).start();

        //Thread.sleep(3000);

        final Settings settings = Settings
                .builder()
                .put("path.home", ".")
                // .putArray("plugin.types", SearchGuardPlugin.class.getName(),
                // SearchGuardSSLPlugin.class.getName())
                //.put("path.conf", "/Users/temp/search-guard2/src/test/resources")
                //.put("path.conf", "/Users/temp/search-guard2/elasticsearch-2.1.0/config")
                .put("path.conf", ".")
                .put("searchguard.ssl.transport.keystore_filepath", ks)
                .put("searchguard.ssl.transport.truststore_filepath", ts)
                .put("searchguard.ssl.transport.keystore_password", kspass)
                .put("searchguard.ssl.transport.truststore_password", tspass)
                .put("searchguard.ssl.transport.enforce_hostname_verification", !nhnv)
                .put("searchguard.ssl.transport.resolve_hostname", !nrhn)
                .put("searchguard.ssl.transport.enabled", true).build();

        try (TransportClient tc = TransportClient.builder().settings(settings).addPlugin(SearchGuardSSLPlugin.class)
                //.addPlugin(SearchGuardPlugin.class)
                .build()
                .addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(hostname, port)))) {

            final ClusterHealthResponse chr = tc.admin().cluster().health(new ClusterHealthRequest().waitForYellowStatus()).actionGet();

            final boolean timedOut = chr.isTimedOut();

            
            if (timedOut) {
                System.out.println("Cluster state is not yellow, timeout");
                return;// System.exit(-1);
            }

            /*System.out.println(chr.getStatus());
            System.out.println(chr.getActivePrimaryShards());
            System.out.println(chr.getActiveShards());
            System.out.println(chr.getInitializingShards());
            System.out.println(chr.getNumberOfDataNodes());
            System.out.println(chr.getNumberOfPendingTasks());
            System.out.println(chr.getRelocatingShards());
            System.out.println(chr.getUnassignedShards());
            System.out.println(chr.getIndices());*/
            
            final boolean indexExists = tc.admin().indices().exists(new IndicesExistsRequest("searchguard")).actionGet().isExists();

            if (!indexExists) {
                System.out.print("searchguard index does not exists, attempt to create it ... ");

                final boolean indexCreated = tc.admin().indices().create(new CreateIndexRequest("searchguard")
                // .mapping("config", source)
                // .settings(settings)
                .settings("index.number_of_shards", 1, "index.number_of_replicas", chr.getNumberOfDataNodes())
                        ).actionGet().isAcknowledged();

                if (indexCreated) {
                    System.out.println("done");
                } else {
                    System.out.println("failed");
                    return;// System.exit(-1);
                }

            } else {
                System.out.println("Index does already exists");
            }
            
            System.out.println("populate config ...");

            try (Reader reader = new FileReader(cd+"/sg_config.yml")) {

                final String id = tc
                        .index(new IndexRequest("searchguard").type("config").id("0").refresh(true)
                                .consistencyLevel(WriteConsistencyLevel.DEFAULT).source(readXContent(reader, XContentType.YAML)))
                                .actionGet().getId();

                if ("0".equals(id)) {
                    System.out.println("Configuration created or updated");
                } else {
                    System.out.println("failed");
                    return;// System.exit(-1);
                }
            }
            try (Reader reader = new FileReader(cd+"/sg_roles.yml")) {

                final String id = tc
                        .index(new IndexRequest("searchguard").type("roles").id("0").refresh(true)
                                .consistencyLevel(WriteConsistencyLevel.DEFAULT).source(readXContent(reader, XContentType.YAML)))
                                .actionGet().getId();

                if ("0".equals(id)) {
                    System.out.println("Roles created or updated");
                } else {
                    System.out.println("failed");
                    return;// System.exit(-1);
                }

            }
            try (Reader reader = new FileReader(cd+"/sg_roles_mapping.yml")) {

                final String id = tc
                        .index(new IndexRequest("searchguard").type("rolesmapping").id("0").refresh(true)
                                .consistencyLevel(WriteConsistencyLevel.DEFAULT).source(readXContent(reader, XContentType.YAML)))
                                .actionGet().getId();

                if ("0".equals(id)) {
                    System.out.println("Role mappings created or updated");
                } else {
                    System.out.println("failed");
                    return;// System.exit(-1);
                }

            }

            try (Reader reader = new FileReader(cd+"/sg_internal_users.yml")) {

                final String id = tc
                        .index(new IndexRequest("searchguard").type("internalusers").id("0").refresh(true)
                                .consistencyLevel(WriteConsistencyLevel.DEFAULT).source(readXContent(reader, XContentType.YAML)))
                                .actionGet().getId();

                if ("0".equals(id)) {
                    System.out.println("Internal users created or updated");
                } else {
                    System.out.println("failed");
                    return;// System.exit(-1);
                }

            }

            try (Reader reader = new FileReader(cd+"/sg_action_groups.yml")) {

                final String id = tc
                        .index(new IndexRequest("searchguard").type("actiongroups").id("0").refresh(true)
                                .consistencyLevel(WriteConsistencyLevel.DEFAULT).source(readXContent(reader, XContentType.YAML)))
                                .actionGet().getId();

                if ("0".equals(id)) {
                    System.out.println("Actiongroups created or updated");
                } else {
                    System.out.println("failed");
                    return;// System.exit(-1);
                }

            }

        }
        // audit changes to .searchguard index

        
        //Thread.sleep(5000);
        System.out.println("Done");

        /*final HttpURLConnection connection = (HttpURLConnection) new URL("http://localhost:9200/").openConnection();
        final String encoded = Base64Helper.encodeBasicHeader("kirk", "testabc");
        connection.setRequestProperty("Authorization", "Basic " + encoded);
        connection.connect();
        System.out.println(IOUtils.toString(connection.getInputStream()));
        System.out.println(connection.getResponseCode());
        */
        
        
        
        
        
        // Thread.sleep(1000*3600);

        /*settings = Settings.builder()
                .put("path.home", ".")
                //.put("plugin.types", SearchGuardPlugin.class.getName())
                .put("request.headers.Authenticate", Base64Helper.encodeBasicHeader("spock","testabc"))
                .build();

        try (TransportClient tc = TransportClient.builder().settings(settings).build()
                .addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(hostname, port)))) {

            tc.index(new IndexRequest("a").type("b").source("{}")).actionGet();

        }



        Thread.sleep(3000);*/

        // sg_roles.yml
        // sg_config.yml

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
