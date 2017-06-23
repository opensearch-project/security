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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Locale;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.action.admin.cluster.node.stats.NodesStatsRequest;
import org.elasticsearch.action.admin.cluster.node.stats.NodesStatsResponse;
import org.elasticsearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.elasticsearch.action.admin.cluster.state.ClusterStateRequest;
import org.elasticsearch.action.admin.cluster.state.ClusterStateResponse;
import org.elasticsearch.action.admin.cluster.tasks.PendingClusterTasksRequest;
import org.elasticsearch.action.admin.cluster.tasks.PendingClusterTasksResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.elasticsearch.action.admin.indices.settings.put.UpdateSettingsResponse;
import org.elasticsearch.action.admin.indices.stats.IndicesStatsRequest;
import org.elasticsearch.action.admin.indices.stats.IndicesStatsResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.NoNodeAvailableException;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.loader.JsonSettingsLoader;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.transport.Netty4Plugin;

import com.floragunn.searchguard.SearchGuardPlugin;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateNodeResponse;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.ConfigConstants;
import com.google.common.io.Files;

public class SearchGuardAdmin {
    
    private static final String SG_TS_PASS = "SG_TS_PASS";
    private static final String SG_KS_PASS = "SG_KS_PASS";
    private static final String SG_KEYPASS = "SG_KEYPASS";
    //not used in multithreaded fashion
    private static SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MMM-dd_HH-mm-ss", Locale.ENGLISH);
    private static final Settings ENABLE_ALL_ALLOCATIONS_SETTINGS = Settings.builder()
            .put("cluster.routing.allocation.enable", "all")
            .build();
    
    public static void main(final String[] args) {
        try {
            main0(args);
        } catch (NoNodeAvailableException e) {
            System.out.println("ERR: Cannot connect to elasticsearch. Please refer to elasticsearch logfile for more information");
            System.out.println("Trace:");
            e.printStackTrace();
            System.exit(-1);
        } 
        catch (IndexNotFoundException e) {
            System.out.println("ERR: No searchguard configuartion index found. Pls. execute sgadmin with different command line parameters");
            System.out.println("When you run it for the first time to not specify -us, -era, -dra or -rl");
            System.out.println("For more informations look here: https://github.com/floragunncom/search-guard/issues/228");
            System.exit(-1);
        }
        catch (Exception e) {
            System.out.println("ERR: An unexpected "+e.getClass().getSimpleName()+" occured: "+e.getMessage());
            System.out.println("Trace:");
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private static void main0(final String[] args) throws Exception {
        
        System.out.println("Search Guard Admin v5");
        System.setProperty("sg.nowarn.client","true");

        final HelpFormatter formatter = new HelpFormatter();
        Options options = new Options();
        options.addOption( "nhnv", "disable-host-name-verification", false, "Disable hostname verification" );
        options.addOption( "nrhn", "disable-resolve-hostname", false, "Disable hostname beeing resolved" );
        options.addOption(Option.builder("ts").longOpt("truststore").hasArg().argName("file").desc("Path to truststore (JKS/PKCS12 format)").build());
        options.addOption(Option.builder("ks").longOpt("keystore").hasArg().argName("file").desc("Path to keystore (JKS/PKCS12 format").build());
        options.addOption(Option.builder("tst").longOpt("truststore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given use file ext. to dectect type").build());
        options.addOption(Option.builder("kst").longOpt("keystore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given use file ext. to dectect type").build());
        options.addOption(Option.builder("tspass").longOpt("truststore-password").hasArg().argName("password").desc("Truststore password").build());
        options.addOption(Option.builder("kspass").longOpt("keystore-password").hasArg().argName("password").desc("Keystore password").build());
        options.addOption(Option.builder("cd").longOpt("configdir").hasArg().argName("directory").desc("Directory for config files").build());
        options.addOption(Option.builder("h").longOpt("hostname").hasArg().argName("host").desc("Elasticsearch host (default: localhost)").build());
        options.addOption(Option.builder("p").longOpt("port").hasArg().argName("port").desc("Elasticsearch transport port (default: 9300)").build());
        options.addOption(Option.builder("cn").longOpt("clustername").hasArg().argName("clustername").desc("Clustername (do not use together with -icl)").build());
        options.addOption( "sniff", "enable-sniffing", false, "Enable client.transport.sniff" );
        options.addOption( "icl", "ignore-clustername", false, "Ignore clustername (do not use together with -cn)" );
        options.addOption(Option.builder("r").longOpt("retrieve").desc("retrieve current config").build());
        options.addOption(Option.builder("f").longOpt("file").hasArg().argName("file").desc("file").build());
        options.addOption(Option.builder("t").longOpt("type").hasArg().argName("file-type").desc("file-type").build());
        options.addOption(Option.builder("tsalias").longOpt("truststore-alias").hasArg().argName("alias").desc("Truststore alias").build());
        options.addOption(Option.builder("ksalias").longOpt("keystore-alias").hasArg().argName("alias").desc("Keystore alias").build());
        options.addOption(Option.builder("ec").longOpt("enabled-ciphers").hasArg().argName("cipers").desc("Comma separated list of TLS ciphers").build());
        options.addOption(Option.builder("ep").longOpt("enabled-protocols").hasArg().argName("protocols").desc("Comma separated list of TLS protocols").build());
        //TODO mark as deprecated and replace it with "era" if "era" is mature enough
        options.addOption(Option.builder("us").longOpt("update_settings").hasArg().argName("number of replicas").desc("update the number of replicas and reload configuration on all nodes and exit").build());
        options.addOption(Option.builder("i").longOpt("index").hasArg().argName("indexname").desc("The index Searchguard uses to store its configs in").build());
        options.addOption(Option.builder("era").longOpt("enable-replica-autoexpand").desc("enable replica auto expand and exit").build());
        options.addOption(Option.builder("dra").longOpt("disable-replica-autoexpand").desc("disable replica auto expand and exit").build());
        options.addOption(Option.builder("rl").longOpt("reload").desc("reload configuration on all nodes and exit").build());
        options.addOption(Option.builder("ff").longOpt("fail-fast").desc("fail-fast if something goes wrong").build());
        options.addOption(Option.builder("dg").longOpt("diagnose").desc("Log diagnostic trace into a file").build());
        options.addOption(Option.builder("dci").longOpt("delete-config-index").desc("Delete 'searchguard' config index and exit.").build());
        options.addOption(Option.builder("esa").longOpt("enable-shard-allocation").desc("Enable all shard allocation and exit.").build());
        options.addOption(Option.builder("arc").longOpt("accept-red-cluster").desc("Also operate on a red cluster. Normally we wait for yellow state.").build());

        options.addOption(Option.builder("cacert").hasArg().argName("file").desc("Path to trusted cacert (PEM format)").build());
        options.addOption(Option.builder("cert").hasArg().argName("file").desc("Path to admin certificate in PEM format").build());
        options.addOption(Option.builder("key").hasArg().argName("file").desc("Path to the key of admin certificate").build());
        options.addOption(Option.builder("keypass").hasArg().argName("password").desc("Password of the key of admin certificate (optional)").build());

        options.addOption(Option.builder("noopenssl").longOpt("no-openssl").desc("Do not use openssl even if available (default: use it if available)").build());

        //when adding new options also adjust validate(CommandLine line)
        
        String hostname = "localhost";
        int port = 9300;
        String kspass = System.getenv(SG_KS_PASS) != null ? System.getenv(SG_KS_PASS) : "changeit";
        String tspass = System.getenv(SG_TS_PASS) != null ? System.getenv(SG_TS_PASS) : kspass;
        String cd = ".";
        String ks;
        String ts;
        String kst = null;
        String tst = null;
        boolean nhnv = false;
        boolean nrhn = false;
        boolean sniff = false;
        boolean icl = false;
        String clustername = "elasticsearch";
        String file = null;
        String type = null;
        boolean retrieve = false;
        String ksAlias = null;
        String tsAlias = null;
        String[] enabledProtocols = new String[0];
        String[] enabledCiphers = new String[0];
        Integer updateSettings = null;
        String index = ConfigConstants.SG_DEFAULT_CONFIG_INDEX;
        Boolean replicaAutoExpand = null;
        boolean reload = false;
        boolean failFast = false;
        boolean diagnose = false;
        boolean deleteConfigIndex = false;
        boolean enableShardAllocation = false;
        boolean acceptRedCluster = false;
        String cacert = null;
        String cert = null;
        String key = null;
        String keypass = System.getenv(SG_KEYPASS);
        boolean useOpenSSLIfAvailable = true;
        
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse( options, args );
            
            validate(line);
            
            hostname = line.getOptionValue("h", hostname);
            port = Integer.parseInt(line.getOptionValue("p", String.valueOf(port)));
            kspass = line.getOptionValue("kspass", kspass); //TODO null? //when no passwd is set
            tspass = line.getOptionValue("tspass", tspass); //TODO null? //when no passwd is set
            cd = line.getOptionValue("cd", cd);
            
            if(!cd.endsWith(File.separator)) {
                cd += File.separator;
            }
            
            ks = line.getOptionValue("ks");
            ts = line.getOptionValue("ts");
            kst = line.getOptionValue("kst", kst);
            tst = line.getOptionValue("tst", tst);
            nhnv = line.hasOption("nhnv");
            nrhn = line.hasOption("nrhn");
            clustername = line.getOptionValue("cn", clustername);
            sniff = line.hasOption("sniff");
            icl = line.hasOption("icl");
            file = line.getOptionValue("f", file);
            type = line.getOptionValue("t", type);
            retrieve = line.hasOption("r");
            ksAlias = line.getOptionValue("ksalias", ksAlias);
            tsAlias = line.getOptionValue("tsalias", tsAlias);
            index = line.getOptionValue("i", index);
            
            String enabledCiphersString = line.getOptionValue("ec", null);
            String enabledProtocolsString = line.getOptionValue("ep", null);
            
            if(enabledCiphersString != null) {
                enabledCiphers = enabledCiphersString.split(",");
            }
            
            if(enabledProtocolsString != null) {
                enabledProtocols = enabledProtocolsString.split(",");
            }
            
            updateSettings = line.hasOption("us")?Integer.parseInt(line.getOptionValue("us")):null;

            reload = line.hasOption("rl");
            
            if(line.hasOption("era")) {
                replicaAutoExpand = true;
            }
            
            if(line.hasOption("dra")) {
                replicaAutoExpand = false;
            }
            
            failFast = line.hasOption("ff");
            diagnose = line.hasOption("dg");
            deleteConfigIndex = line.hasOption("dci");
            enableShardAllocation = line.hasOption("esa");
            acceptRedCluster = line.hasOption("arc");
            
            cacert = line.getOptionValue("cacert");
            cert = line.getOptionValue("cert");
            key = line.getOptionValue("key");
            keypass = line.getOptionValue("keypass");
            
            useOpenSSLIfAvailable = !line.hasOption("noopenssl");
            
        }
        catch( ParseException exp ) {
            System.err.println("ERR: Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("sgadmin.sh", options, true);
            return;
        }
        
        if(port < 9300) {
            System.out.println("WARNING: Seems you want connect to the a HTTP port."+System.lineSeparator()
                             + "         sgadmin connect through the transport port which is normally 9300.");
        }
        
        System.out.print("Will connect to "+hostname+":"+port);
        Socket socket = new Socket();
        
        try {
            
            socket.connect(new InetSocketAddress(hostname, port));
            
          } catch (java.net.ConnectException ex) {
            System.out.println();
            System.out.println("ERR: Seems there is no elasticsearch running on "+hostname+":"+port+" - Will exit");
            System.exit(-1);
          } finally {
              try {
                socket.close();
            } catch (Exception e) {
                //ignore
            }
          }

        System.out.println(" ... done");
        
        final Settings.Builder settingsBuilder = Settings
                .builder()
                .put("path.home", ".")
                .put("path.conf", ".")
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, kspass)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, tspass)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, !nhnv)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, !nrhn)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, useOpenSSLIfAvailable)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, kst==null?(ks.endsWith(".jks")?"JKS":"PKCS12"):kst)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE, tst==null?(ts.endsWith(".jks")?"JKS":"PKCS12"):tst)
                
                .putArray(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_CIPHERS, enabledCiphers)
                .putArray(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_PROTOCOLS, enabledProtocols)
                
                .put("cluster.name", clustername)
                .put("client.transport.ignore_cluster_name", icl)
                .put("client.transport.sniff", sniff);
                
                if(ksAlias != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, ksAlias);
                }
                
                if(tsAlias != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS, tsAlias);
                }
                
                if(ks != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, ks);
                }
                
                if(ts != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, ts);
                }            
                
                if(cacert != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, cacert);
                }
                
                if(cert != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMCERT_FILEPATH, cert);
                }
                
                if(key != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_FILEPATH, key);
                }
                
                if(keypass != null) {
                    settingsBuilder.put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_PASSWORD, keypass);
                }

                Settings settings = settingsBuilder.build();  

        try (TransportClient tc = new TransportClientImpl(settings, asCollection(Netty4Plugin.class, SearchGuardPlugin.class))
                .addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(hostname, port)))) {

            if(updateSettings != null) { 
                Settings indexSettings = Settings.builder().put("index.number_of_replicas", updateSettings).build();                
                tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();                
                final UpdateSettingsResponse response = tc.admin().indices().updateSettings((new UpdateSettingsRequest(index).settings(indexSettings))).actionGet();
                System.out.println("Reload config on all nodes");
                System.out.println("Update number of replicas to "+(updateSettings) +" with result: "+response.isAcknowledged());
                System.exit(response.isAcknowledged()?0:-1);
            }
            
            if(reload) { 
                tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();                
                System.out.println("Reload config on all nodes");
                System.exit(0);
            }
            
            if(replicaAutoExpand != null) { 
                Settings indexSettings = Settings.builder()
                        .put("index.auto_expand_replicas", replicaAutoExpand?"0-all":"false")
                        .build();                
                tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();                
                final UpdateSettingsResponse response = tc.admin().indices().updateSettings((new UpdateSettingsRequest(index).settings(indexSettings))).actionGet();
                System.out.println("Reload config on all nodes");
                System.out.println("Auto-expand replicas "+(replicaAutoExpand?"enabled":"disabled"));
                System.exit(response.isAcknowledged()?0:-1);
            }   
            
            if(enableShardAllocation) { 
                final boolean successful = tc.admin().cluster()
                        .updateSettings(new ClusterUpdateSettingsRequest()
                        .transientSettings(ENABLE_ALL_ALLOCATIONS_SETTINGS)
                        .persistentSettings(ENABLE_ALL_ALLOCATIONS_SETTINGS))
                        .actionGet()
                        .isAcknowledged();
                
                if(successful) {
                    System.out.println("Persistent and transient shard allocation enabled");
                } else {
                    System.out.println("ERR: Unable to enable shard allocation");
                }
                
                System.exit(successful?0:-1);
            }   
            
            if(failFast) {
                System.out.println("Failfast is activated");
            }
            
            if(diagnose) {
                generateDiagnoseTrace(tc);
            }
            
            System.out.println("Contacting elasticsearch cluster '"+clustername+"'"+(acceptRedCluster?"":" and wait for YELLOW clusterstate")+" ...");
            
            ClusterHealthResponse chr = null;
            
            while(chr == null) {
                try {
                    final ClusterHealthRequest chrequest = new ClusterHealthRequest().timeout(TimeValue.timeValueMinutes(5));
                    if(!acceptRedCluster) {
                        chrequest.waitForYellowStatus();
                    }
                    chr = tc.admin().cluster().health(chrequest).actionGet();
                } catch (Exception e) {                   
                    if(!failFast) {
                        System.out.println("Cannot retrieve cluster state due to: "+e.getMessage()+". This is not an error, will keep on trying ...");
                        System.out.println("   * Try running sgadmin.sh with -icl and -nhnv (If thats works you need to check your clustername as well as hostnames in your SSL certificates)");   
                        System.out.println("   * If this is not working, try running sgadmin.sh with --diagnose and see diagnose trace log file)");
                        System.out.println("   * Add --accept-red-cluster to allow sgadmin to operate on a red cluster.");

                    } else {
                        System.out.println("ERR: Cannot retrieve cluster state due to: "+e.getMessage()+".");
                        System.out.println("   * Try running sgadmin.sh with -icl and -nhnv (If thats works you need to check your clustername as well as hostnames in your SSL certificates)");
                        System.out.println("   * If this is not working, try running sgadmin.sh with --diagnose and see diagnose trace log file)"); 
                        System.out.println("   * Add --accept-red-cluster to allow sgadmin to operate on a red cluster.");

                        System.exit(-1);
                    }
                    
                    Thread.sleep(3000);
                    continue;
                }
            }

            final boolean timedOut = chr.isTimedOut();
            
            if (!acceptRedCluster && timedOut) {
                System.out.println("ERR: Timed out while waiting for a green or yellow cluster state.");
                System.out.println("   * Try running sgadmin.sh with -icl and -nhnv (If thats works you need to check your clustername as well as hostnames in your SSL certificates)");
                System.out.println("   * If this is not working, try running sgadmin.sh with --diagnose and see diagnose trace log file)"); 
                System.out.println("   * Add --accept-red-cluster to allow sgadmin to operate on a red cluster.");
                System.exit(-1);
            }
            
            System.out.println("Clustername: "+chr.getClusterName());
            System.out.println("Clusterstate: "+chr.getStatus());
            System.out.println("Number of nodes: "+chr.getNumberOfNodes());
            System.out.println("Number of data nodes: "+chr.getNumberOfDataNodes());
            
            final boolean indexExists = tc.admin().indices().exists(new IndicesExistsRequest(index)).actionGet().isExists();
            
            final NodesInfoResponse nodesInfo = tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();

            if(deleteConfigIndex) {
                
                boolean success = true;
                
                if(indexExists) {
                    success = tc.admin().indices().delete(new DeleteIndexRequest(index)).actionGet().isAcknowledged();
                    System.out.print("Deleted index '"+index+"'");
                } else {
                    System.out.print("No index '"+index+"' exists, so no need to delete it");
                }
                
                System.exit(success?0:-1);
            }
               
            if (!indexExists) {
                System.out.print(index +" index does not exists, attempt to create it ... ");
                final boolean indexCreated = tc.admin().indices().create(new CreateIndexRequest(index)
                .settings(
                        "index.number_of_shards", 1, 
                        "index.auto_expand_replicas", "0-all"
                        ))
                        .actionGet().isAcknowledged();

                if (indexCreated) {
                    System.out.println("done (auto expand replicas is on)");
                } else {
                    System.out.println("failed!");
                    System.out.println("FAIL: Unable to create the "+index+" index. See elasticsearch logs for more details");
                    System.exit(-1);
                }

            } else {
                System.out.println(index+" index already exists, so we do not need to create one.");
                
                try {
                    ClusterHealthResponse chrsg = tc.admin().cluster().health(new ClusterHealthRequest(index)).actionGet();
                             
                    if (chrsg.isTimedOut()) {
                        System.out.println("ERR: Timed out while waiting for "+index+" index state.");
                    }
                    
                    if (chrsg.getStatus() == ClusterHealthStatus.RED) {
                        System.out.println("ERR: "+index+" index state is RED.");
                    }
                    
                    if (chrsg.getStatus() == ClusterHealthStatus.YELLOW) {
                        System.out.println("INFO: "+index+" index state is YELLOW, it seems you miss some replicas");
                    }
                    
                } catch (Exception e) {
                    if(!failFast) {
                        System.out.println("Cannot retrieve "+index+" index state state due to "+e.getMessage()+". This is not an error, will keep on trying ...");
                    } else {
                        System.out.println("ERR: Cannot retrieve "+index+" index state state due to "+e.getMessage()+".");
                        System.exit(-1);
                    }
                }
            }
            
            if(retrieve) {
                String date = DATE_FORMAT.format(new Date());
                
                boolean success = retrieveFile(tc, cd+"sg_config_"+date+".yml", index, "config");
                success = success & retrieveFile(tc, cd+"sg_roles_"+date+".yml", index, "roles");
                success = success & retrieveFile(tc, cd+"sg_roles_mapping_"+date+".yml", index, "rolesmapping");
                success = success & retrieveFile(tc, cd+"sg_internal_users_"+date+".yml", index, "internalusers");
                success = success & retrieveFile(tc, cd+"sg_action_groups_"+date+".yml", index, "actiongroups");
                System.exit(success?0:-1);
            }
            
            boolean isCdAbs = new File(cd).isAbsolute();
             
            System.out.println("Populate config from "+(isCdAbs?cd:new File(".", cd).getCanonicalPath()));
            
            if(file != null) {
                if(type == null) {
                    System.out.println("ERR: type missing");
                    System.exit(-1);
                }
                
                if(!Arrays.asList(new String[]{"config", "roles", "rolesmapping", "internalusers","actiongroups" }).contains(type)) {
                    System.out.println("ERR: Invalid type '"+type+"'");
                    System.exit(-1);
                }
                
                boolean success = uploadFile(tc, file, index, type);
                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{type})).actionGet();
                
                success = success & checkConfigUpdateResponse(cur, nodesInfo, 1);
                
                System.out.println("Done with "+(success?"success":"failures"));
                System.exit(success?0:-1);
            }

            boolean success = uploadFile(tc, cd+"sg_config.yml", index, "config");
            success = success & uploadFile(tc, cd+"sg_roles.yml", index, "roles");
            success = success & uploadFile(tc, cd+"sg_roles_mapping.yml", index, "rolesmapping");
            success = success & uploadFile(tc, cd+"sg_internal_users.yml", index, "internalusers");
            success = success & uploadFile(tc, cd+"sg_action_groups.yml", index, "actiongroups");
            
            if(failFast && !success) {
                System.out.println("ERR: cannot upload configuration, see errors above");
                System.exit(-1);
            }
            
            ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{"config","roles","rolesmapping","internalusers","actiongroups"})).actionGet();
            
            success = success & checkConfigUpdateResponse(cur, nodesInfo, 5);
            
            System.out.println("Done with "+(success?"success":"failures"));
            System.exit(success?0:-1);
        }
        // TODO audit changes to searchguard index
    }

    private static boolean checkConfigUpdateResponse(ConfigUpdateResponse response, NodesInfoResponse nir, int expectedConfigCount) {
        
        int expectedNodeCount = 0;
        
        for(NodeInfo ni: nir.getNodes()) {
            Settings nodeSettings = ni.getSettings();
          
            //do not count tribe clients
            if(nodeSettings.get("tribe.name", null) == null) {
                expectedNodeCount++;
            }           
        }

        boolean success = response.getNodes().size() == expectedNodeCount;
        if(!success) {
            System.out.println("FAIL: Expected "+expectedNodeCount+" nodes to return response, but got only "+response.getNodes().size());
        }
        
        for(String nodeId: response.getNodesMap().keySet()) {
            ConfigUpdateNodeResponse node = response.getNodesMap().get(nodeId);
            boolean successNode = (node.getUpdatedConfigTypes() != null && node.getUpdatedConfigTypes().length == expectedConfigCount);
            
            if(!successNode) {
                System.out.println("FAIL: Expected "+expectedConfigCount+" config types for node "+nodeId+" but got only "+Arrays.toString(node.getUpdatedConfigTypes()) + " due to: "+node.getMessage()==null?"unknown reason":node.getMessage());
            }
            
            success = success & successNode;
        }
        
        return success;
    }
    
    private static boolean uploadFile(Client tc, String filepath, String index, String type) {
        System.out.println("Will update '" + type + "' with " + filepath);
        try (Reader reader = new FileReader(filepath)) {

            final String id = tc
                    .index(new IndexRequest(index).type(type).id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                            .source(type, readXContent(reader, XContentType.YAML))).actionGet().getId();

            if ("0".equals(id)) {
                System.out.println("   SUCC: Configuration for '" + type + "' created or updated");
                return true;
            } else {
                System.out.println("   FAIL: Configuration for '" + type
                        + "' failed for unknown reasons. Pls. consult logfile of elasticsearch");
            }
        } catch (Exception e) {
            System.out.println("   FAIL: Configuration for '" + type + "' failed because of " + e.toString());
        }

        return false;
    }
    
    private static boolean retrieveFile(Client tc, String filepath, String index, String type) {
        System.out.println("Will retrieve '"+type+"' into "+filepath);
        try (Writer writer = new FileWriter(filepath)) {

            final GetResponse response = tc.get(new GetRequest(index).type(type).id("0").refresh(true).realtime(false)).actionGet();

            if (response.isExists()) {
                if(response.isSourceEmpty()) {
                    System.out.println("   FAIL: Configuration for '"+type+"' failed because of empty source");
                    return false;
                }
                
                String yaml = convertToYaml(type, response.getSourceAsBytesRef(), true);
                writer.write(yaml);
                System.out.println("   SUCC: Configuration for '"+type+"' stored in "+filepath);
                return true;
            } else {
                System.out.println("   FAIL: Get configuration for '"+type+"' because it does not exist");
            }
        } catch (Exception e) {
            System.out.println("   FAIL: Get configuration for '"+type+"' failed because of "+e.toString());
        }
        
        return false;
    }

    private static BytesReference readXContent(final Reader reader, final XContentType xContentType) throws IOException {
        BytesReference retVal;
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(reader);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            retVal = builder.bytes();
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
        
        //validate
        Settings.builder().put(new JsonSettingsLoader(true).load(XContentHelper.createParser(retVal))).build();
        return retVal;
    }
    
    private static String convertToYaml(String type, BytesReference bytes, boolean prettyPrint) throws IOException {
        
        try (XContentParser parser = XContentFactory.xContent(XContentFactory.xContentType(bytes)).createParser(bytes.streamInput())) {
            
            parser.nextToken();
            parser.nextToken();
            
            if(!type.equals((parser.currentName()))) {
                return null;
            }
            
            parser.nextToken();
            
            XContentBuilder builder = XContentFactory.yamlBuilder();
            if (prettyPrint) {
                builder.prettyPrint();
            }
            builder.rawValue(new BytesArray(parser.binaryValue()));
            return builder.string();
        }
    }

    protected static class TransportClientImpl extends TransportClient {

        public TransportClientImpl(Settings settings, Collection<Class<? extends Plugin>> plugins) {
            super(settings, plugins);
        }

        public TransportClientImpl(Settings settings, Settings defaultSettings, Collection<Class<? extends Plugin>> plugins) {
            super(settings, defaultSettings, plugins, null);
        }       
    }
    
    protected static Collection<Class<? extends Plugin>> asCollection(Class<? extends Plugin>... plugins) {
        return Arrays.asList(plugins);
    }

    protected static void generateDiagnoseTrace(final Client tc) {
        
        final String date = DATE_FORMAT.format(new Date());
        
        final StringBuilder sb = new StringBuilder();
        sb.append("Diagnostic sgadmin trace"+System.lineSeparator());
        sb.append("ES client version: "+Version.CURRENT+System.lineSeparator());
        sb.append("Client properties: "+System.getProperties()+System.lineSeparator());
        sb.append(date+System.lineSeparator());
        sb.append(System.lineSeparator());
        
        try {
            sb.append("ClusterHealthRequest:"+System.lineSeparator());
            ClusterHealthResponse nir = tc.admin().cluster().health(new ClusterHealthRequest()).actionGet();
            sb.append(XContentHelper.toString(nir));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"NodesInfoResponse:"+System.lineSeparator());
            NodesInfoResponse nir = tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();
            sb.append(XContentHelper.toString(nir));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"NodesStatsRequest:"+System.lineSeparator());
            NodesStatsResponse nir = tc.admin().cluster().nodesStats(new NodesStatsRequest()).actionGet();
            sb.append(XContentHelper.toString(nir));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"PendingClusterTasksRequest:"+System.lineSeparator());
            PendingClusterTasksResponse nir = tc.admin().cluster().pendingClusterTasks(new PendingClusterTasksRequest()).actionGet();
            sb.append(XContentHelper.toString(nir));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"ClusterStateRequest:"+System.lineSeparator());
            ClusterStateResponse nir = tc.admin().cluster().state(new ClusterStateRequest()).actionGet();
            sb.append(XContentHelper.toString(nir.getState()));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"IndicesStatsRequest:"+System.lineSeparator());
            IndicesStatsResponse nir = tc.admin().indices().stats(new IndicesStatsRequest()).actionGet();
            sb.append(XContentHelper.toString(nir));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            File dfile = new File("sgadmin_diag_trace_"+date+".txt");
            Files.write(sb,dfile,Charset.forName("UTF-8"));
            System.out.println("Diagnostic trace written to: "+dfile.getAbsolutePath());
        } catch (Exception e1) {
            System.out.println("ERR: cannot write diag trace file due to "+e1);
        }
    }
    
    private static void validate(CommandLine line) throws ParseException{
        
        if(line.hasOption("ts") && line.hasOption("cacert")) {
            System.out.println("WARN: It makes no sense to specify -ts as well as -cacert");
        }
        
        if(line.hasOption("ks") && line.hasOption("cert")) {
            System.out.println("WARN: It makes no sense to specify -ks as well as -cert");
        }
        
        if(line.hasOption("ks") && line.hasOption("key")) {
            System.out.println("WARN: It makes no sense to specify -ks as well as -key");
        }
        
        if(line.hasOption("cd") && line.hasOption("r")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -r");
        }
        
        if(line.hasOption("cd") && line.hasOption("rl")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -r");
        }
        
        if(line.hasOption("cd") && line.hasOption("f")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -f");
        }
        
        if(line.hasOption("cn") && line.hasOption("icl")) {
            throw new ParseException("Only set one of -cn or -icl");
        }
        
        //TODO add more validation rules
    }
}
