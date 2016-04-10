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

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.net.InetSocketAddress;
import java.util.Arrays;

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
import org.elasticsearch.client.Client;
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
        options.addOption(Option.builder("cn").longOpt("clustername").hasArg().argName("clustername").desc("Clustername").build());
        options.addOption( "sniff", "enable-sniffing", false, "Enable client.transport.sniff" );
        options.addOption( "icl", "ignore-clustername", false, "Ignore clustername" );
        options.addOption(Option.builder("f").longOpt("file").hasArg().argName("file").desc("file").build());
        options.addOption(Option.builder("t").longOpt("type").hasArg().argName("file-type").desc("file-type").build());
        
        String hostname = "localhost";
        int port = 9300;
        String kspass = "changeit";
        String tspass = kspass;
        String cd = ".";
        String ks;
        String ts;
        boolean nhnv = false;
        boolean nrhn = false;
        boolean sniff = false;
        boolean icl = false;
        String clustername = "elasticsearch";
        String file = null;
        String type = null;
        
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
            clustername = line.getOptionValue("cn", clustername);
            sniff = line.hasOption("sniff");
            icl = line.hasOption("icl");
            file = line.getOptionValue("f", file);
            type = line.getOptionValue("t", type);
        }
        catch( ParseException exp ) {
            System.err.println("Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("sgadmin.sh", options, true);
            return;
        }
        
        
        System.out.println("Connect to "+hostname+":"+port);

        final Settings settings = Settings
                .builder()
                .put("path.home", ".")
                .put("path.conf", ".")
                .put("searchguard.ssl.transport.keystore_filepath", ks)
                .put("searchguard.ssl.transport.truststore_filepath", ts)
                .put("searchguard.ssl.transport.keystore_password", kspass)
                .put("searchguard.ssl.transport.truststore_password", tspass)
                .put("searchguard.ssl.transport.enforce_hostname_verification", !nhnv)
                .put("searchguard.ssl.transport.resolve_hostname", !nrhn)
                .put("searchguard.ssl.transport.enabled", true)
                .put("cluster.name", clustername)
                .put("client.transport.ignore_cluster_name", icl)
                .put("client.transport.sniff", sniff)
                .build();

        try (TransportClient tc = TransportClient.builder().settings(settings).addPlugin(SearchGuardSSLPlugin.class)
                .build()
                .addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(hostname, port)))) {

            final ClusterHealthResponse chr = tc.admin().cluster().health(new ClusterHealthRequest().waitForYellowStatus()).actionGet();

            final boolean timedOut = chr.isTimedOut();

            
            if (timedOut) {
                System.out.println("Cluster state timeout");
                System.exit(-1);
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
            
            if(file != null) {
                if(type == null) {
                    System.out.println("type missing");
                    System.exit(-1);
                }
                
                if(!Arrays.asList(new String[]{"config", "roles", "rolesmapping", "internalusers","actiongroups" }).contains(type)) {
                    System.out.println("Invalid type '"+type+"'");
                    System.exit(-1);
                }
                
                boolean success = uploadFile(tc, file, type);
                System.exit(success?0:-1);
            }

            boolean success = uploadFile(tc, cd+"/sg_config.yml", "config");
            success = success & uploadFile(tc, cd+"/sg_roles.yml", "roles");
            success = success & uploadFile(tc, cd+"/sg_roles_mapping.yml", "rolesmapping");
            success = success & uploadFile(tc, cd+"/sg_internal_users.yml", "internalusers");
            success = success & uploadFile(tc, cd+"/sg_action_groups.yml", "actiongroups");
            
            System.out.println("Wait a short time ...");
            Thread.sleep(5000);
            System.out.println("Done with "+(success?"success":"failures"));
            System.exit(success?0:-1);
        }
        // TODO audit changes to .searchguard index
    }
    
    private static boolean uploadFile(Client tc, String filepath, String type) {
        System.out.println("Will update '"+type+"' with "+filepath);
        try (Reader reader = new FileReader(filepath)) {

            final String id = tc
                    .index(new IndexRequest("searchguard").type(type).id("0").refresh(true)
                            .consistencyLevel(WriteConsistencyLevel.DEFAULT).source(readXContent(reader, XContentType.YAML)))
                            .actionGet().getId();

            if ("0".equals(id)) {
                System.out.println("   SUCC Configuration for '"+type+"' created or updated");
                return true;
            } else {
                System.out.println("   FAIL Configuration for '"+type+"' failed for unknown reasons. Pls. consult logfile of elasticsearch");
            }
        } catch (IOException e) {
            System.out.println("   FAIL Configuration for '"+type+"' failed because of "+e.toString());
        }
        
        return false;
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
