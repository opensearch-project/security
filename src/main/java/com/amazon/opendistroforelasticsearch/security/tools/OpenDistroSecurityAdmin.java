/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.tools;

import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.NodesDn;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.WhitelistingSettings;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.opensearch.OpenSearchException;
import org.opensearch.ExceptionsHelper;
import org.opensearch.Version;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.opensearch.action.admin.cluster.node.info.PluginsAndModules;
import org.opensearch.action.admin.cluster.node.stats.NodesStatsRequest;
import org.opensearch.action.admin.cluster.node.stats.NodesStatsResponse;
import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.opensearch.action.admin.cluster.tasks.PendingClusterTasksRequest;
import org.opensearch.action.admin.cluster.tasks.PendingClusterTasksResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexRequest.Feature;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.admin.indices.stats.IndicesStatsRequest;
import org.opensearch.action.admin.indices.stats.IndicesStatsResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.transport.NoNodeAvailableException;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.Strings;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.transport.Netty4Plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateAction;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateNodeResponse;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.action.whoami.WhoAmIAction;
import com.amazon.opendistroforelasticsearch.security.action.whoami.WhoAmIRequest;
import com.amazon.opendistroforelasticsearch.security.action.whoami.WhoAmIResponse;
import com.amazon.opendistroforelasticsearch.security.securityconf.Migration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.RoleMappingsV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.InternalUserV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleMappingsV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.RoleV7;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.TenantV7;
import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecuritySSLPlugin;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigHelper;
import com.amazon.opendistroforelasticsearch.security.support.SecurityJsonNode;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;
import com.google.common.io.CharStreams;
import com.google.common.io.Files;

import static org.opensearch.common.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;

@SuppressWarnings("deprecation")
public class OpenDistroSecurityAdmin {

    private static final boolean CREATE_AS_LEGACY = Boolean.parseBoolean(System.getenv("OPENDISTRO_SECURITY_ADMIN_CREATE_AS_LEGACY"));
    private static final boolean ALLOW_MIXED = Boolean.parseBoolean(System.getenv("OPENDISTRO_SECURITY_ADMIN_ALLOW_MIXED_CLUSTER"));
    private static final String OPENDISTRO_SECURITY_TS_PASS = "OPENDISTRO_SECURITY_TS_PASS";
    private static final String OPENDISTRO_SECURITY_KS_PASS = "OPENDISTRO_SECURITY_KS_PASS";
    private static final String OPENDISTRO_SECURITY_KEYPASS = "OPENDISTRO_SECURITY_KEYPASS";
    //not used in multithreaded fashion, so it's okay to define it as a constant here
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MMM-dd_HH-mm-ss", Locale.ENGLISH); //NOSONAR
    private static final Settings ENABLE_ALL_ALLOCATIONS_SETTINGS = Settings.builder()
            .put("cluster.routing.allocation.enable", "all")
            .build();
    
    public static void main(final String[] args) {
        try {
            final int returnCode = execute(args);
            System.exit(returnCode);
        } catch (NoNodeAvailableException e) {
            System.out.println("ERR: Cannot connect to OpenSearch. Please refer to opensearch logfile for more information");
            System.out.println("Trace:");
            System.out.println(ExceptionsHelper.stackTrace(e));
            System.out.println();
            System.exit(-1);
        } 
        catch (IndexNotFoundException e) {
            System.out.println("ERR: No Open Distro Security configuration index found. Please execute securityadmin with different command line parameters");
            System.out.println("When you run it for the first time do not specify -us, -era, -dra or -rl");
            System.out.println();
            System.exit(-1);
        }
        catch (Throwable e) {
            
            if (e instanceof OpenSearchException
                    && e.getMessage() != null 
                    && e.getMessage().contains("no permissions")) {

                System.out.println("ERR: You try to connect with a TLS node certificate instead of an admin client certificate");                
                System.out.println();
                System.exit(-1);
            }
            
            System.out.println("ERR: An unexpected "+e.getClass().getSimpleName()+" occured: "+e.getMessage());
            System.out.println("Trace:");
            System.out.println(ExceptionsHelper.stackTrace(e));
            System.out.println();
            System.exit(-1);
        }
    }

    public static int execute(final String[] args) throws Exception {
        
        System.out.println("Open Distro Security Admin v7");
        System.setProperty("security.nowarn.client","true");
        System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation","true");

        final HelpFormatter formatter = new HelpFormatter();
        Options options = new Options();
        options.addOption( "nhnv", "disable-host-name-verification", false, "Disable hostname verification" );
        options.addOption( "nrhn", "disable-resolve-hostname", false, "Disable DNS lookup of hostnames" );
        options.addOption(Option.builder("ts").longOpt("truststore").hasArg().argName("file").desc("Path to truststore (JKS/PKCS12 format)").build());
        options.addOption(Option.builder("ks").longOpt("keystore").hasArg().argName("file").desc("Path to keystore (JKS/PKCS12 format").build());
        options.addOption(Option.builder("tst").longOpt("truststore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given we use the file extension to dectect the type").build());
        options.addOption(Option.builder("kst").longOpt("keystore-type").hasArg().argName("type").desc("JKS or PKCS12, if not given we use the file extension to dectect the type").build());
        options.addOption(Option.builder("tspass").longOpt("truststore-password").hasArg().argName("password").desc("Truststore password").build());
        options.addOption(Option.builder("kspass").longOpt("keystore-password").hasArg().argName("password").desc("Keystore password").build());
        options.addOption(Option.builder("cd").longOpt("configdir").hasArg().argName("directory").desc("Directory for config files").build());
        options.addOption(Option.builder("h").longOpt("hostname").hasArg().argName("host").desc("OpenSearch host (default: localhost)").build());
        options.addOption(Option.builder("p").longOpt("port").hasArg().argName("port").desc("OpenSearch transport port (default: 9300)").build());
        options.addOption(Option.builder("cn").longOpt("clustername").hasArg().argName("clustername").desc("Clustername (do not use together with -icl)").build());
        options.addOption( "sniff", "enable-sniffing", false, "Enable client.transport.sniff" );
        options.addOption( "icl", "ignore-clustername", false, "Ignore clustername (do not use together with -cn)" );
        options.addOption(Option.builder("r").longOpt("retrieve").desc("retrieve current config").build());
        options.addOption(Option.builder("f").longOpt("file").hasArg().argName("file").desc("file").build());
        options.addOption(Option.builder("t").longOpt("type").hasArg().argName("file-type").desc("file-type").build());
        options.addOption(Option.builder("tsalias").longOpt("truststore-alias").hasArg().argName("alias").desc("Truststore alias").build());
        options.addOption(Option.builder("ksalias").longOpt("keystore-alias").hasArg().argName("alias").desc("Keystore alias").build());
        options.addOption(Option.builder("ec").longOpt("enabled-ciphers").hasArg().argName("cipers").desc("Comma separated list of enabled TLS ciphers").build());
        options.addOption(Option.builder("ep").longOpt("enabled-protocols").hasArg().argName("protocols").desc("Comma separated list of enabled TLS protocols").build());
        //TODO mark as deprecated and replace it with "era" if "era" is mature enough
        options.addOption(Option.builder("us").longOpt("update_settings").hasArg().argName("number of replicas").desc("Update the number of Open Distro Security index replicas, reload configuration on all nodes and exit").build());
        options.addOption(Option.builder("i").longOpt("index").hasArg().argName("indexname").desc("The index Open Distro Security uses to store the configuration").build());
        options.addOption(Option.builder("era").longOpt("enable-replica-autoexpand").desc("Enable replica auto expand and exit").build());
        options.addOption(Option.builder("dra").longOpt("disable-replica-autoexpand").desc("Disable replica auto expand and exit").build());
        options.addOption(Option.builder("rl").longOpt("reload").desc("Reload the configuration on all nodes, flush all Open Distro Security caches and exit").build());
        options.addOption(Option.builder("ff").longOpt("fail-fast").desc("fail-fast if something goes wrong").build());
        options.addOption(Option.builder("dg").longOpt("diagnose").desc("Log diagnostic trace into a file").build());
        options.addOption(Option.builder("dci").longOpt("delete-config-index").desc("Delete '.opendistro_security' config index and exit.").build());
        options.addOption(Option.builder("esa").longOpt("enable-shard-allocation").desc("Enable all shard allocation and exit.").build());
        options.addOption(Option.builder("arc").longOpt("accept-red-cluster").desc("Also operate on a red cluster. If not specified the cluster state has to be at least yellow.").build());

        options.addOption(Option.builder("cacert").hasArg().argName("file").desc("Path to trusted cacert (PEM format)").build());
        options.addOption(Option.builder("cert").hasArg().argName("file").desc("Path to admin certificate in PEM format").build());
        options.addOption(Option.builder("key").hasArg().argName("file").desc("Path to the key of admin certificate").build());
        options.addOption(Option.builder("keypass").hasArg().argName("password").desc("Password of the key of admin certificate (optional)").build());

        options.addOption(Option.builder("noopenssl").longOpt("no-openssl").desc("Do not use OpenSSL even if available (default: use it if available)").build());

        options.addOption(Option.builder("si").longOpt("show-info").desc("Show system and license info").build());

        options.addOption(Option.builder("w").longOpt("whoami").desc("Show information about the used admin certificate").build());

        options.addOption(Option.builder("prompt").longOpt("prompt-for-password").desc("Prompt for password if not supplied").build());

        options.addOption(Option.builder("er").longOpt("explicit-replicas").hasArg().argName("number of replicas").desc("Set explicit number of replicas or autoexpand expression for .opendistro_security index").build());

        options.addOption(Option.builder("backup").hasArg().argName("folder").desc("Backup configuration to folder").build());

        options.addOption(Option.builder("migrate").hasArg().argName("folder").desc("Migrate and use folder to store migrated files").build());
        
        options.addOption(Option.builder("rev").longOpt("resolve-env-vars").desc("Resolve/Substitute env vars in config with their value before uploading").build());

        options.addOption(Option.builder("vc").numberOfArgs(1).optionalArg(true).argName("version").longOpt("validate-configs").desc("Validate config for version 6 or 7 (default 7)").build());

        options.addOption(Option.builder("mo").longOpt("migrate-offline").hasArg().argName("folder").desc("Migrate and use folder to store migrated files").build());

        
        //when adding new options also adjust validate(CommandLine line)
        
        String hostname = "localhost";
        int port = 9300;
        String kspass = System.getenv(OPENDISTRO_SECURITY_KS_PASS);
        String tspass = System.getenv(OPENDISTRO_SECURITY_TS_PASS);
        String cd = ".";
        String ks = null;
        String ts = null;
        String kst = null;
        String tst = null;
        boolean nhnv = false;
        boolean nrhn = false;
        boolean sniff = false;
        boolean icl = false;
        String clustername = "opensearch";
        String file = null;
        String type = null;
        boolean retrieve = false;
        String ksAlias = null;
        String tsAlias = null;
        String[] enabledProtocols = new String[0];
        String[] enabledCiphers = new String[0];
        Integer updateSettings = null;
        String index = ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
        Boolean replicaAutoExpand = null;
        boolean reload = false;
        boolean failFast = false;
        boolean diagnose = false;
        boolean deleteConfigIndex = false;
        boolean enableShardAllocation = false;
        boolean acceptRedCluster = false;
        
        String keypass = System.getenv(OPENDISTRO_SECURITY_KEYPASS);
        boolean useOpenSSLIfAvailable = true;
        //boolean simpleAuth = false;
        String cacert = null;
        String cert = null;
        String key = null;
        boolean si;
        boolean whoami;
        final boolean promptForPassword;
        String explicitReplicas = null;
        String backup = null;
        String migrate = null;
        final boolean resolveEnvVars;
        Integer validateConfig = null;
        String migrateOffline = null;
        
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse( options, args );
            
            validate(line);
            
            hostname = line.getOptionValue("h", hostname);
            port = Integer.parseInt(line.getOptionValue("p", String.valueOf(port)));

            promptForPassword = line.hasOption("prompt");
            
            if(kspass == null || kspass.isEmpty()) {
                kspass = line.getOptionValue("kspass",promptForPassword?null:"changeit");
            }
            
            if(tspass == null || tspass.isEmpty()) {
                tspass = line.getOptionValue("tspass",promptForPassword?null:kspass);
            }

            cd = line.getOptionValue("cd", cd);
            
            if(!cd.endsWith(File.separator)) {
                cd += File.separator;
            }
            
            ks = line.getOptionValue("ks",ks);
            ts = line.getOptionValue("ts",ts);
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
            keypass = line.getOptionValue("keypass", keypass);
            
            useOpenSSLIfAvailable = !line.hasOption("noopenssl");
            
            si = line.hasOption("si");
            
            whoami = line.hasOption("w");
            
            explicitReplicas = line.getOptionValue("er", explicitReplicas);
            
            backup = line.getOptionValue("backup");
            
            migrate = line.getOptionValue("migrate");
            
            resolveEnvVars = line.hasOption("rev");
            
            validateConfig = !line.hasOption("vc")?null:Integer.parseInt(line.getOptionValue("vc", "7"));
            
            if(validateConfig != null && validateConfig.intValue() != 6 && validateConfig.intValue() != 7) {
                throw new ParseException("version must be 6 or 7");
            }
            
            migrateOffline = line.getOptionValue("mo");
            
        }
        catch( ParseException exp ) {
            System.out.println("ERR: Parsing failed.  Reason: " + exp.getMessage());
            formatter.printHelp("securityadmin.sh", options, true);
            return -1;
        }
        
        
        if(validateConfig != null) {
            System.out.println("Validate configuration for Version "+validateConfig.intValue());
            return validateConfig(cd, file, type, validateConfig.intValue());
        }
        
        if(migrateOffline != null) {
            System.out.println("Migrate "+migrateOffline+" offline");
            final boolean retVal =  Migrater.migrateDirectory(new File(migrateOffline), true);
            return retVal?0:-1;
        }
        
        
        if(port < 9300) {
            System.out.println("WARNING: Seems you want connect to the OpenSearch HTTP port."+System.lineSeparator()
                             + "         securityadmin connects on the transport port which is normally 9300.");
        }
        
        System.out.print("Will connect to "+hostname+":"+port);
        Socket socket = new Socket();
        
        try {
            
            socket.connect(new InetSocketAddress(hostname, port));
            
          } catch (java.net.ConnectException ex) {
            System.out.println();
            System.out.println("ERR: Seems there is no OpenSearch running on "+hostname+":"+port+" - Will exit");
            return (-1);
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
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, !nhnv)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, !nrhn)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED, true)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, OpenDistroSecuritySSLPlugin.OPENSSL_SUPPORTED && useOpenSSLIfAvailable)
                .putList(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, enabledCiphers)
                .putList(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, enabledProtocols)
                
                .put("cluster.name", clustername)
                .put("client.transport.ignore_cluster_name", icl)
                .put("client.transport.sniff", sniff);
                
                if(ksAlias != null) {
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, ksAlias);
                }
                
                if(tsAlias != null) {
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS, tsAlias);
                }
                
                if(ks != null) {
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH, ks);
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE, kst==null?(ks.endsWith(".jks")?"JKS":"PKCS12"):kst);
                    
                    if(kspass == null && promptForPassword) {
                        kspass = promptForPassword("Keystore", "kspass", OPENDISTRO_SECURITY_KS_PASS);
                    }
                    
                    if(kspass != null) {
                        settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD, kspass);
                    }
                }
                
                if(ts != null) {
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, ts);
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE, tst==null?(ts.endsWith(".jks")?"JKS":"PKCS12"):tst);
                    
                    if(tspass == null && promptForPassword) {
                        tspass = promptForPassword("Truststore", "tspass", OPENDISTRO_SECURITY_TS_PASS);
                    }
                    
                    if(tspass != null) {
                        settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, tspass);
                    }
                }            
                
                if(cacert != null) {
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, cacert);
                }
                
                if(cert != null) {
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, cert);
                }
                
                if(key != null) {
                    settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, key);
                    
                    if(keypass == null && promptForPassword) {
                        keypass = promptForPassword("Pemkey", "keypass", OPENDISTRO_SECURITY_KEYPASS);
                    }
                    
                    if(keypass != null) {
                        settingsBuilder.put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD, keypass);
                    }
                }

                Settings settings = settingsBuilder.build();  

        try (@SuppressWarnings("resource")
        TransportClient tc = new TransportClientImpl(settings, asCollection(Netty4Plugin.class, OpenDistroSecurityPlugin.class))
                .addTransportAddress(new TransportAddress(new InetSocketAddress(hostname, port)))) {

            
            final WhoAmIResponse whoAmIRes = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();
            System.out.println("Connected as "+whoAmIRes.getDn());

            if(!whoAmIRes.isAdmin()) {
                
            	System.out.println("ERR: "+whoAmIRes.getDn()+" is not an admin user");
                
                if(!whoAmIRes.isNodeCertificateRequest()) {
                	System.out.println("Seems you use a client certificate but this one is not registered as admin_dn");
                	System.out.println("Make sure opensearch.yml on all nodes contains:");
                    System.out.println("opendistro_security.authcz.admin_dn:"+System.lineSeparator()+
                                       "  - \""+whoAmIRes.getDn()+"\"");
                } else {
                	System.out.println("Seems you use a node certificate. This is not permitted, you have to use a client certificate and register it as admin_dn in opensearch.yml");
                }
                return (-1);
            } else if(whoAmIRes.isNodeCertificateRequest()) {
                System.out.println("ERR: Seems you use a node certificate which is also an admin certificate");
                System.out.println("     That may have worked with older Open Distro Security versions but it indicates");
                System.out.println("     a configuration error and is therefore forbidden now.");
                if (failFast) {
                    return (-1);
                }

            }

            try {
                if(issueWarnings(tc) != 0) {
                    return (-1);
                }
            } catch (Exception e1) {
                System.out.println("Unable to check whether cluster is sane");
                throw e1;
            }

            if(updateSettings != null) { 
                Settings indexSettings = Settings.builder().put("index.number_of_replicas", updateSettings).build();
                ConfigUpdateResponse res = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(getTypes(true))).actionGet();
                if(res.hasFailures()) {
                    System.out.println("ERR: Unabe to reload config due to "+res.failures());
                }
                final AcknowledgedResponse response = tc.admin().indices().updateSettings((new UpdateSettingsRequest(index).settings(indexSettings))).actionGet();
                System.out.println("Reload config on all nodes");
                System.out.println("Update number of replicas to "+(updateSettings) +" with result: "+response.isAcknowledged());
                return ((response.isAcknowledged() && !res.hasFailures())?0:-1);
            }
            
            if(reload) { 
                ConfigUpdateResponse res = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(getTypes(false))).actionGet();                
                if(res.hasFailures()) {
                    System.out.println("ERR: Unabe to reload config due to "+res.failures());
                    return -1;
                }
                System.out.println("Reload config on all nodes");
                return 0;
            }
            
            if(si) {
                return (0);
            }
            
            if(whoami) { 
                System.out.println(whoAmIRes.toString());
                return (0);
            }
            
            
            if(replicaAutoExpand != null) { 
                Settings indexSettings = Settings.builder()
                        .put("index.auto_expand_replicas", replicaAutoExpand?"0-all":"false")
                        .build();                
                ConfigUpdateResponse res = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(getTypes(false))).actionGet();                
                if(res.hasFailures()) {
                    System.out.println("ERR: Unabe to reload config due to "+res.failures());
                }
                final AcknowledgedResponse response = tc.admin().indices().updateSettings((new UpdateSettingsRequest(index).settings(indexSettings))).actionGet();
                System.out.println("Reload config on all nodes");
                System.out.println("Auto-expand replicas "+(replicaAutoExpand?"enabled":"disabled"));
                return ((response.isAcknowledged() && !res.hasFailures())?0:-1);
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
                
                return (successful?0:-1);
            }   
            
            if(failFast) {
                System.out.println("Fail-fast is activated");
            }
            
            if(diagnose) {
                generateDiagnoseTrace(tc);
            }
            
            System.out.println("Contacting opensearch cluster '"+clustername+"'"+(acceptRedCluster?"":" and wait for YELLOW clusterstate")+" ...");
            
            ClusterHealthResponse chr = null;
            
            while(chr == null) {
                try {
                    final ClusterHealthRequest chrequest = new ClusterHealthRequest().timeout(TimeValue.timeValueMinutes(5));
                    if(!acceptRedCluster) {
                        chrequest.waitForYellowStatus();
                    }
                    chr = tc.admin().cluster().health(chrequest).actionGet();
                } catch (Exception e) {
                    
                    Throwable rootCause = ExceptionUtils.getRootCause(e);
                    
                    if(!failFast) {
                        System.out.println("Cannot retrieve cluster state due to: "+e.getMessage()+". This is not an error, will keep on trying ...");
                        System.out.println("  Root cause: "+rootCause+" ("+e.getClass().getName()+"/"+rootCause.getClass().getName()+")");
                        System.out.println("   * Try running securityadmin.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");   
                        System.out.println("   * Make sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                        System.out.println("   * If this is not working, try running securityadmin.sh with --diagnose and see diagnose trace log file)");
                        System.out.println("   * Add --accept-red-cluster to allow securityadmin to operate on a red cluster.");

                    } else {
                        System.out.println("ERR: Cannot retrieve cluster state due to: "+e.getMessage()+".");
                        System.out.println("  Root cause: "+rootCause+" ("+e.getClass().getName()+"/"+rootCause.getClass().getName()+")");
                        System.out.println("   * Try running securityadmin.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");
                        System.out.println("   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                        System.out.println("   * If this is not working, try running securityadmin.sh with --diagnose and see diagnose trace log file)"); 
                        System.out.println("   * Add --accept-red-cluster to allow securityadmin to operate on a red cluster.");

                        return (-1);
                    }
                    
                    Thread.sleep(3000);
                    continue;
                }
            }

            final boolean timedOut = chr.isTimedOut();
            
            if (!acceptRedCluster && timedOut) {
                System.out.println("ERR: Timed out while waiting for a green or yellow cluster state.");
                System.out.println("   * Try running securityadmin.sh with -icl (but no -cl) and -nhnv (If that works you need to check your clustername as well as hostnames in your TLS certificates)");
                System.out.println("   * Make also sure that your keystore or PEM certificate is a client certificate (not a node certificate) and configured properly in opensearch.yml");
                System.out.println("   * If this is not working, try running securityadmin.sh with --diagnose and see diagnose trace log file)"); 
                System.out.println("   * Add --accept-red-cluster to allow securityadmin to operate on a red cluster.");
                return (-1);
            }
            
            System.out.println("Clustername: "+chr.getClusterName());
            System.out.println("Clusterstate: "+chr.getStatus());
            System.out.println("Number of nodes: "+chr.getNumberOfNodes());
            System.out.println("Number of data nodes: "+chr.getNumberOfDataNodes());
            
            GetIndexResponse securityIndex = null;
            try {
                securityIndex = tc.admin().indices().getIndex(new GetIndexRequest().indices(index).addFeatures(Feature.MAPPINGS)).actionGet();
            } catch (IndexNotFoundException e1) {
                //ignore
            }
            final boolean indexExists = securityIndex != null;
            
            final NodesInfoResponse nodesInfo = tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();

            if(deleteConfigIndex) {
                return deleteConfigIndex(tc, index, indexExists);
            }
               
            if (!indexExists) {
                System.out.print(index +" index does not exists, attempt to create it ... ");
                final int created = createConfigIndex(tc, index, explicitReplicas);
                if(created != 0) {
                    return created;
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
                        return (-1);
                    }
                }
            }

            final boolean createLegacyMode = !indexExists && CREATE_AS_LEGACY;

            if(createLegacyMode) {
                System.out.println("We forcibly create the new index in legacy mode so that ES 6 config can be uploaded. To move to v7 configs youneed to migrate.");
            }

            final boolean legacy = createLegacyMode || (indexExists
                    && securityIndex.getMappings() != null
                    && securityIndex.getMappings().get(index) != null
                    && securityIndex.getMappings().get(index).containsKey("security"));
            
            if(legacy) {
                System.out.println("Legacy index '"+index+"' (ES 6) detected (or forced). You should migrate the configuration!");
            }
            
            if(retrieve) {
                String date = DATE_FORMAT.format(new Date());
                
                boolean success = retrieveFile(tc, cd+"config_"+date+".yml", index, "config", legacy);
                success = retrieveFile(tc, cd+"roles_"+date+".yml", index, "roles", legacy) && success;
                success = retrieveFile(tc, cd+"roles_mapping_"+date+".yml", index, "rolesmapping", legacy) && success;
                success = retrieveFile(tc, cd+"internal_users_"+date+".yml", index, "internalusers", legacy) && success;
                success = retrieveFile(tc, cd+"action_groups_"+date+".yml", index, "actiongroups", legacy) && success;
                success = retrieveFile(tc, cd+"audit_"+date+".yml", index, "audit", legacy) && success;

                if(!legacy) {
                    success = retrieveFile(tc, cd+"security_tenants_"+date+".yml", index, "tenants", legacy) && success;
                }

                final boolean populateFileIfEmpty = true;
                success = retrieveFile(tc, cd+"nodes_dn_"+date+".yml", index, "nodesdn", legacy, populateFileIfEmpty) && success;
                success = retrieveFile(tc, cd+"whitelist_"+date+".yml", index, "whitelist", legacy, populateFileIfEmpty) && success;
                return (success?0:-1);
            }

            if(backup != null) {
                return backup(tc, index, new File(backup), legacy);
            }

            if(migrate != null) {
                if(!legacy) {
                    System.out.println("ERR: Seems cluster is already migrated");
                    return -1;
                }
                return migrate(tc, index, new File(migrate), nodesInfo, resolveEnvVars);
            }

            boolean isCdAbs = new File(cd).isAbsolute();
             
            System.out.println("Populate config from "+(isCdAbs?cd:new File(".", cd).getCanonicalPath()));
            
            if(file != null) {
                if(type != null) {
                    System.out.println("Force type: "+type);
                } else {
                    type = readTypeFromFile(new File(file));
                    if(type == null) {
                        System.out.println("ERR: Unable to read type from file");
                        return (-1);
                    }
                }

                if(!CType.lcStringValues().contains(type)) {
                    System.out.println("ERR: Invalid type '"+type+"'");
                    return (-1);
                }

                boolean success = uploadFile(tc, file, index, type, legacy, resolveEnvVars);

                if(!success) {
                    System.out.println("ERR: cannot upload configuration, see errors above");
                    return -1;
                }

                ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(new String[]{type})).actionGet();
                
                success = checkConfigUpdateResponse(cur, nodesInfo, 1) && success;
                
                System.out.println("Done with "+(success?"success":"failures"));
                return (success?0:-1);
            }

            return upload(tc, index, cd, legacy, nodesInfo, resolveEnvVars);
        }
        // TODO audit changes to .opendistro_security index
    }

    private static boolean checkConfigUpdateResponse(ConfigUpdateResponse response, NodesInfoResponse nir, int expectedConfigCount) {

        final int expectedNodeCount =  nir.getNodes().size();

        if(response.hasFailures()) {
            System.out.println("FAIL: "+response.failures().size()+" nodes reported failures. First failure is "+response.failures().get(0));
        }

        boolean success = response.getNodes().size() == expectedNodeCount;
        if(!success) {
            System.out.println("FAIL: Expected "+expectedNodeCount+" nodes to return response, but got "+response.getNodes().size());
        }
        
        for(String nodeId: response.getNodesMap().keySet()) {
            ConfigUpdateNodeResponse node = response.getNodesMap().get(nodeId);
            boolean successNode = (node.getUpdatedConfigTypes() != null && node.getUpdatedConfigTypes().length == expectedConfigCount);
            if(!successNode) {
                System.out.println("FAIL: Expected "+expectedConfigCount+" config types for node "+nodeId+" but got "+node.getUpdatedConfigTypes().length+" ("+Arrays.toString(node.getUpdatedConfigTypes()) + ") due to: "+(node.getMessage()==null?"unknown reason":node.getMessage()));
            }
            
            success = success && successNode;
        }

        return success && !response.hasFailures();
    }

    private static boolean uploadFile(final Client tc, final String filepath, final String index, final String _id, final boolean legacy, boolean resolveEnvVars) {
        return uploadFile(tc, filepath, index, _id, legacy, resolveEnvVars, false);
    }

    private static boolean uploadFile(final Client tc, final String filepath, final String index, final String _id, final boolean legacy, boolean resolveEnvVars,
        final boolean populateEmptyIfMissing) {
        
        String type = "_doc";
        String id = _id;
                
        if(legacy) {
            type = "security";
            id = _id;

            try {
                ConfigHelper.fromYamlFile(filepath, CType.fromString(_id), 1, 0, 0);
            } catch (Exception e) {
                System.out.println("ERR: Seems "+filepath+" is not in legacy format: "+e);
                return false;
            }

        } else {
            try {
                ConfigHelper.fromYamlFile(filepath, CType.fromString(_id), 2, 0, 0);
            } catch (Exception e) {
                System.out.println("ERR: Seems "+filepath+" is not in Open Distro Security 7 format: "+e);
                return false;
            }
        }

        System.out.println("Will update '"+type+"/" + id + "' with " + filepath+" "+(legacy?"(legacy mode)":""));
        
        try (Reader reader = ConfigHelper.createFileOrStringReader(CType.fromString(_id), legacy ? 1 : 2, filepath, populateEmptyIfMissing)) {
            final String content = CharStreams.toString(reader);
            final String res = tc
                    .index(new IndexRequest(index).type(type).id(id).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                            .source(_id, readXContent(resolveEnvVars?OpenDistroSecurityUtils.replaceEnvVars(content, Settings.EMPTY):content, XContentType.YAML))).actionGet().getId();

            if (id.equals(res)) {
                System.out.println("   SUCC: Configuration for '" + _id + "' created or updated");
                return true;
            } else {
                System.out.println("   FAIL: Configuration for '" + _id
                        + "' failed for unknown reasons. Please consult the OpenSearch logfile.");
            }
        } catch (Exception e) {
            System.out.println("   FAIL: Configuration for '" + _id + "' failed because of " + e.toString());
        }

        return false;
    }

    private static boolean retrieveFile(final Client tc, final String filepath, final String index, final String _id, final boolean legacy) {
        return retrieveFile(tc, filepath, index, _id, legacy, false);
    }

    private static boolean retrieveFile(final Client tc, final String filepath, final String index, final String _id, final boolean legacy, final boolean populateFileIfEmpty) {
        
        String type = "_doc";
        String id = _id;
                
        if(legacy) {
            type = "security";
            id = _id;
            
        }
        
        System.out.println("Will retrieve '"+type+"/" +id+"' into "+filepath+" "+(legacy?"(legacy mode)":""));
        try (Writer writer = new FileWriter(filepath)) {

            final GetResponse response = tc.get(new GetRequest(index).type(type).id(id).refresh(true).realtime(false)).actionGet();

            boolean isEmpty = !response.isExists() || response.isSourceEmpty();
            String yaml;
            if (isEmpty) {
                if (populateFileIfEmpty) {
                    yaml = ConfigHelper.createEmptySdcYaml(CType.fromString(_id), legacy ? 1 : 2);
                } else {
                    System.out.println("   FAIL: Configuration for '"+_id+"' failed because of empty source");
                    return false;
                }
            } else {
                yaml = convertToYaml(_id, response.getSourceAsBytesRef(), true);

                if (null == yaml) {
                    System.out.println("ERR: YML conversion error for " + _id);
                    return false;

                }

                if (legacy) {
                    try {
                        ConfigHelper.fromYamlString(yaml, CType.fromString(_id), 1, 0, 0);
                    } catch (Exception e) {
                        System.out.println("ERR: Seems " + _id + " from cluster is not in legacy format: " + e);
                        return false;
                    }
                } else {
                    try {
                        ConfigHelper.fromYamlString(yaml, CType.fromString(_id), 2, 0, 0);
                    } catch (Exception e) {
                        System.out.println("ERR: Seems " + _id + " from cluster is not in SG 7 format: " + e);
                        return false;
                    }
                }
            }

            writer.write(yaml);
            System.out.println("   SUCC: Configuration for '"+_id+"' stored in "+filepath);
            return true;
        } catch (Exception e) {
            System.out.println("   FAIL: Get configuration for '"+_id+"' failed because of "+e.toString());
        }
        
        return false;
    }

    private static BytesReference readXContent(final String content, final XContentType xContentType) throws IOException {
        BytesReference retVal;
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, content);
            parser.nextToken();
            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.copyCurrentStructure(parser);
            retVal = BytesReference.bytes(builder);
        } finally {
            if (parser != null) {
                parser.close();
            }
        }
        
        //validate
        return retVal;
    }
    
    private static String convertToYaml(String type, BytesReference bytes, boolean prettyPrint) throws IOException {
        
        try (XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, bytes.streamInput())) {
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
            builder.rawValue(new ByteArrayInputStream(parser.binaryValue()), XContentType.YAML);
            return Strings.toString(builder);
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
    
    @SafeVarargs
    protected static Collection<Class<? extends Plugin>> asCollection(Class<? extends Plugin>... plugins) {
        return Arrays.asList(plugins);
    }

    protected static void generateDiagnoseTrace(final Client tc) {
        
        final String date = DATE_FORMAT.format(new Date());
        
        final StringBuilder sb = new StringBuilder();
        sb.append("Diagnostic securityadmin trace"+System.lineSeparator());
        sb.append("OpenSearch client version: "+Version.CURRENT+System.lineSeparator());
        sb.append("Client properties: "+System.getProperties()+System.lineSeparator());
        sb.append(date+System.lineSeparator());
        sb.append(System.lineSeparator());
        
        try {
            sb.append("Who am i:"+System.lineSeparator());
            final WhoAmIResponse whoAmIRes = tc.execute(WhoAmIAction.INSTANCE, new WhoAmIRequest()).actionGet();
            sb.append(Strings.toString(whoAmIRes,true, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append("ClusterHealthRequest:"+System.lineSeparator());
            ClusterHealthResponse nir = tc.admin().cluster().health(new ClusterHealthRequest()).actionGet();
            sb.append(Strings.toString(nir,true, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"NodesInfoResponse:"+System.lineSeparator());
            NodesInfoResponse nir = tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();
            sb.append(Strings.toString(nir,true, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"NodesStatsRequest:"+System.lineSeparator());
            NodesStatsResponse nir = tc.admin().cluster().nodesStats(new NodesStatsRequest()).actionGet();
            sb.append(Strings.toString(nir,true, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"PendingClusterTasksRequest:"+System.lineSeparator());
            PendingClusterTasksResponse nir = tc.admin().cluster().pendingClusterTasks(new PendingClusterTasksRequest()).actionGet();
            sb.append(Strings.toString(nir,true, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            sb.append(System.lineSeparator()+"IndicesStatsRequest:"+System.lineSeparator());
            IndicesStatsResponse nir = tc.admin().indices().stats(new IndicesStatsRequest()).actionGet();
            sb.append(Strings.toString(nir, true, true));
        } catch (Exception e1) {
            sb.append(ExceptionsHelper.stackTrace(e1));
        }
        
        try {
            File dfile = new File("securityadmin_diag_trace_"+date+".txt");
            Files.asCharSink(dfile, StandardCharsets.UTF_8).write(sb);
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
        
        if(line.hasOption("cd") && line.hasOption("rl")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -r");
        }
        
        if(line.hasOption("cd") && line.hasOption("f")) {
            System.out.println("WARN: It makes no sense to specify -cd as well as -f");
        }

        if(line.hasOption("cn") && line.hasOption("icl")) {
            throw new ParseException("Only set one of -cn or -icl");
        }

        if(line.hasOption("vc") && !line.hasOption("cd") && !line.hasOption("f")) {
            throw new ParseException("Specify at least -cd or -f together with vc");
        }

        if(!line.hasOption("vc") && !line.hasOption("ks") && !line.hasOption("cert") /*&& !line.hasOption("simple-auth")*/) {
            throw new ParseException("Specify at least -ks or -cert");
        }
        
        if(!line.hasOption("vc")  && !line.hasOption("mo") 
                && !line.hasOption("ts") && !line.hasOption("cacert")) {
            throw new ParseException("Specify at least -ts or -cacert");
        }
        
        //TODO add more validation rules
    }
    
    private static String promptForPassword(String passwordName, String commandLineOption, String envVarName) throws Exception {
        final Console console = System.console();
        if(console == null) {
            throw new Exception("Cannot allocate a console. Set env var "+envVarName+" or "+commandLineOption+" on commandline in that case");
        }
        return new String(console.readPassword("[%s]", passwordName+" password:"));
    }
    
    private static int issueWarnings(Client tc) {
        NodesInfoResponse nir = tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet();
        Version maxVersion = nir.getNodes().stream().max((n1,n2) -> n1.getVersion().compareTo(n2.getVersion())).get().getVersion();
        Version minVersion = nir.getNodes().stream().min((n1,n2) -> n1.getVersion().compareTo(n2.getVersion())).get().getVersion();
        
        if(!maxVersion.equals(minVersion)) {
            System.out.println("ERR: Your cluster consists of different node versions. It is not allowed to run securityadmin against a mixed cluster.");
            System.out.println("         Minimum node version is "+minVersion.toString());
            System.out.println("         Maximum node version is "+maxVersion.toString());
            if(!ALLOW_MIXED) {
                return -1;
            }
           
        } else {
            System.out.println("OpenSearch Version: "+minVersion.toString());
        }
        
        if(nir.getNodes().size() > 0) {
            List<PluginInfo> pluginInfos = nir.getNodes().get(0).getInfo(PluginsAndModules.class).getPluginInfos();
            String securityVersion = pluginInfos.stream().filter(p->p.getClassname().equals("com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin")).map(p->p.getVersion()).findFirst().orElse("<unknown>");
            System.out.println("Open Distro Security Version: "+securityVersion);
        }
        
        return 0;
    }
    
    private static int deleteConfigIndex(TransportClient tc, String index, boolean indexExists) {
        boolean success = true;
        
        if(indexExists) {
            success = tc.admin().indices().delete(new DeleteIndexRequest(index)).actionGet().isAcknowledged();
            System.out.print("Deleted index '"+index+"'");
        } else {
            System.out.print("No index '"+index+"' exists, so no need to delete it");
        }
        
        return (success?0:-1);
    }
    
    private static int createConfigIndex(TransportClient tc, String index, String explicitReplicas) {
        Map<String, Object> indexSettings = new HashMap<>();
        indexSettings.put("index.number_of_shards", 1);
        
        if(explicitReplicas != null) {
            if(explicitReplicas.contains("-")) {
                indexSettings.put("index.auto_expand_replicas", explicitReplicas);
            } else {
                indexSettings.put("index.number_of_replicas", Integer.parseInt(explicitReplicas));
            }
        } else {
            indexSettings.put("index.auto_expand_replicas", "0-all");
        }

        final boolean indexCreated = tc.admin().indices().create(new CreateIndexRequest(index)
        .settings(indexSettings))
                .actionGet().isAcknowledged();

        if (indexCreated) {
            System.out.println("done ("+(explicitReplicas!=null?explicitReplicas:"0-all")+" replicas)");
            return 0;
        } else {
            System.out.println("failed!");
            System.out.println("FAIL: Unable to create the "+index+" index. See opensearch logs for more details");
            return (-1);
        }
    }
    
    private static int backup(TransportClient tc, String index, File backupDir, boolean legacy) {
        backupDir.mkdirs();
        
        boolean success = retrieveFile(tc, backupDir.getAbsolutePath()+"/config.yml", index, "config", legacy);
        success = retrieveFile(tc, backupDir.getAbsolutePath()+"/roles.yml", index, "roles", legacy) && success;
        
        success = retrieveFile(tc, backupDir.getAbsolutePath()+"/roles_mapping.yml", index, "rolesmapping", legacy) && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath()+"/internal_users.yml", index, "internalusers", legacy) && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath()+"/action_groups.yml", index, "actiongroups", legacy) && success;
        
        if(!legacy) {
            success = retrieveFile(tc, backupDir.getAbsolutePath()+"/tenants.yml", index, "tenants", legacy) && success;
        }
        success = retrieveFile(tc, backupDir.getAbsolutePath()+"/nodes_dn.yml", index, "nodesdn", legacy, true) && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath()+"/whitelist.yml", index, "whitelist", legacy, true) && success;
        success = retrieveFile(tc, backupDir.getAbsolutePath() + "/audit.yml", index, "audit", legacy) && success;

        return success?0:-1;
    }
    
    private static int upload(TransportClient tc, String index, String cd, boolean legacy, NodesInfoResponse nodesInfo, boolean resolveEnvVars) {
        boolean success = uploadFile(tc, cd+"config.yml", index, "config", legacy, resolveEnvVars);
        success = uploadFile(tc, cd+"roles.yml", index, "roles", legacy, resolveEnvVars) && success;
        success = uploadFile(tc, cd+"roles_mapping.yml", index, "rolesmapping", legacy, resolveEnvVars) && success;
        
        success = uploadFile(tc, cd+"internal_users.yml", index, "internalusers", legacy, resolveEnvVars) && success;
        success = uploadFile(tc, cd+"action_groups.yml", index, "actiongroups", legacy, resolveEnvVars) && success;

        
        if(!legacy) {
            success = uploadFile(tc, cd+"tenants.yml", index, "tenants", legacy, resolveEnvVars) && success;
        }

        success = uploadFile(tc, cd+"nodes_dn.yml", index, "nodesdn", legacy, resolveEnvVars, true) && success;
        success = uploadFile(tc, cd+"whitelist.yml", index, "whitelist", legacy, resolveEnvVars) && success;
        if (new File(cd+"audit.yml").exists()) {
            success = uploadFile(tc, cd + "audit.yml", index, "audit", legacy, resolveEnvVars) && success;
        }

        if(!success) {
            System.out.println("ERR: cannot upload configuration, see errors above");
            return -1;
        }
        
        ConfigUpdateResponse cur = tc.execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(getTypes(legacy))).actionGet();

        success = checkConfigUpdateResponse(cur, nodesInfo, getTypes(legacy).length) && success;

        System.out.println("Done with "+(success?"success":"failures"));
        return (success?0:-1);
    }
    
    private static int migrate(TransportClient tc, String index, File backupDir, NodesInfoResponse nodesInfo, boolean resolveEnvVars) {
        
        System.out.println("== Migration started ==");
        System.out.println("=======================");
        
        System.out.println("-> Backup current configuration to "+backupDir.getAbsolutePath());
        
        if(backup(tc, index, backupDir, true) != 0) {
            return -1;
        }

        System.out.println("  done");
        
        File v7Dir = new File(backupDir,"v7");
        v7Dir.mkdirs();
        
        try {

            System.out.println("-> Migrate configuration to new format and store it here: "+v7Dir.getAbsolutePath());
            SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsV7 = Migration.migrateActionGroups(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(new File(backupDir,"action_groups.yml")), CType.ACTIONGROUPS, 1, 0, 0));
            SecurityDynamicConfiguration<ConfigV7> configV7 = Migration.migrateConfig(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(new File(backupDir,"config.yml")), CType.CONFIG, 1, 0, 0));
            SecurityDynamicConfiguration<InternalUserV7> internalUsersV7 = Migration.migrateInternalUsers(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(new File(backupDir,"internal_users.yml")), CType.INTERNALUSERS, 1, 0, 0));
            SecurityDynamicConfiguration<RoleMappingsV6> rolesmappingV6 = SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(new File(backupDir,"roles_mapping.yml")), CType.ROLESMAPPING, 1, 0, 0);
            Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesTenantsV7 = Migration.migrateRoles(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(new File(backupDir,"roles.yml")), CType.ROLES, 1, 0, 0), rolesmappingV6);
            SecurityDynamicConfiguration<RoleMappingsV7> rolesmappingV7 = Migration.migrateRoleMappings(rolesmappingV6);
            SecurityDynamicConfiguration<NodesDn> nodesDn =
                Migration.migrateNodesDn(SecurityDynamicConfiguration.fromNode(
                    DefaultObjectMapper.YAML_MAPPER.readTree(ConfigHelper.createFileOrStringReader(CType.NODESDN, 1, new File(backupDir,"nodes_dn.yml").getAbsolutePath(), true)),
                    CType.NODESDN, 1, 0, 0));
            SecurityDynamicConfiguration<WhitelistingSettings> whitelistingSettings =
                    Migration.migrateWhitelistingSetting(SecurityDynamicConfiguration.fromNode(
                            DefaultObjectMapper.YAML_MAPPER.readTree(ConfigHelper.createFileOrStringReader(CType.WHITELIST, 1, new File(backupDir,"whitelist.yml").getAbsolutePath(), true)),
                            CType.WHITELIST, 1, 0, 0));
            SecurityDynamicConfiguration<AuditConfig> audit = Migration.migrateAudit(SecurityDynamicConfiguration.fromNode(DefaultObjectMapper.YAML_MAPPER.readTree(new File(backupDir,"audit.yml")), CType.AUDIT, 1, 0, 0));

            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/action_groups.yml"), actionGroupsV7);
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/config.yml"), configV7);
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/internal_users.yml"), internalUsersV7);
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/roles.yml"), rolesTenantsV7.v1());
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/tenants.yml"), rolesTenantsV7.v2());
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/roles_mapping.yml"), rolesmappingV7);
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/nodes_dn.yml"), nodesDn);
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/whitelist.yml"), whitelistingSettings);
            DefaultObjectMapper.YAML_MAPPER.writeValue(new File(v7Dir, "/audit.yml"), audit);

        } catch (Exception e) {
            System.out.println("ERR: Unable to migrate config files due to "+e);
            e.printStackTrace();
            return -1;
        }
        
        System.out.println("  done");
        
        System.out.println("-> Delete old "+index+" index");
        deleteConfigIndex(tc, index, true);
        System.out.println("  done");
        
        System.out.println("-> Upload new configuration into OpenSearch cluster");

        int uploadResult = upload(tc, index, v7Dir.getAbsolutePath()+"/", false, nodesInfo, resolveEnvVars);

        if(uploadResult == 0) {
            System.out.println("  done");
        }else {
            System.out.println("  ERR: unable to upload");
        }
        
        return uploadResult;
    }
    
    private static String readTypeFromFile(File file) throws IOException {
        if(!file.exists() || !file.isFile()) {
            System.out.println("ERR: No such file "+file.getAbsolutePath());
            return null;
        }
        final JsonNode jsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(file);
        return new SecurityJsonNode(jsonNode).get("_meta").get("type").asString();
    }

    private static int validateConfig(String cd, String file, String type, int version) {
        if (file != null) {
            try {
                
                if(type == null) {
                    type = readTypeFromFile(new File(file));
                }
                
                if(type == null) {
                    System.out.println("ERR: Unable to read type from "+file);
                    return -1;
                }
                
                ConfigHelper.fromYamlFile(file, CType.fromString(type), version==7?2:1, 0, 0);
                return 0;
            } catch (Exception e) {
                System.out.println("ERR: Seems "+file+" is not in SG "+version+" format: "+e);
                return -1;
            }
        } else if(cd != null) {
            boolean success = validateConfigFile(cd+"action_groups.yml", CType.ACTIONGROUPS, version);
            success = validateConfigFile(cd+"internal_users.yml", CType.INTERNALUSERS, version) && success;
            success = validateConfigFile(cd+"roles.yml", CType.ROLES, version) && success;
            success = validateConfigFile(cd+"roles_mapping.yml", CType.ROLESMAPPING, version) && success;
            success = validateConfigFile(cd+"config.yml", CType.CONFIG, version) && success;
            
            if(new File(cd+"tenants.yml").exists() && version != 6) {
                success = validateConfigFile(cd+"tenants.yml", CType.TENANTS, version) && success;
            }
            if (new File(cd+"audit.yml").exists()) {
                success = validateConfigFile(cd+"audit.yml", CType.AUDIT, version) && success;
            }

            return success?0:-1;

        }
        
        return -1;
    }
    
    private static boolean validateConfigFile(String file, CType cType, int version) {
        try {
            ConfigHelper.fromYamlFile(file, cType, version==7?2:1, 0, 0);
            System.out.println(file+" OK" );
            return true;
        } catch (Exception e) {
            System.out.println("ERR: Seems "+file+" is not in SG "+version+" format: "+e);
            return false;
        }
    }
    
    private static String[] getTypes(boolean legacy) {
        if(legacy) {
            return new String[]{"config","roles","rolesmapping","internalusers","actiongroups","nodesdn", "audit"};
        }
        return CType.lcStringValues().toArray(new String[0]);
    }
}
